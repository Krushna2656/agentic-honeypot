import os
import time
import hashlib
from typing import Dict, Any, List, Optional

import requests
from fastapi import FastAPI, Header, HTTPException

from app.schemas import IncomingMessage
from app.detector import detect_scam
from app.extractor import extract_features
from app.agent import agent_decision

app = FastAPI(title="Agentic Honeypot API")

# ✅ API KEY: ENV first, fallback local
API_KEY = os.getenv("HONEYPOT_API_KEY", "Honeypot2026@Krushna")

# ✅ GUVI callback endpoint (mandatory)
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)

# -----------------------------
# Simple in-memory session store
# -----------------------------
SESSION_STORE: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Helpers: Unique merge
# -----------------------------
def merge_unique(a, b):
    return list(dict.fromkeys((a or []) + (b or [])))


# -----------------------------
# Evidence helpers: confidence + sourceTurn
# -----------------------------
def _base_confidence(field: str) -> float:
    return {
        "upiIds": 0.92,
        "phishingLinks": 0.88,
        "bankAccounts": 0.86,
        "ifscCodes": 0.93,
        "phoneNumbers": 0.80,
        "emailIds": 0.78
    }.get(field, 0.70)


def _add_evidence(
    store: Dict[str, Dict[str, Any]],
    field: str,
    values: List[str],
    turn: int,
    confidence_override: Optional[float] = None
):
    if not values:
        return

    conf = confidence_override if confidence_override is not None else _base_confidence(field)
    if field not in store:
        store[field] = {}

    for v in values:
        key = (v or "").strip()
        if not key:
            continue

        if key not in store[field]:
            store[field][key] = {"value": key, "confidence": conf, "sourceTurn": turn}
        else:
            if conf > store[field][key]["confidence"]:
                store[field][key]["confidence"] = conf
            if turn < store[field][key]["sourceTurn"]:
                store[field][key]["sourceTurn"] = turn


def _finalize_evidence(store: Dict[str, Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for field, by_value in store.items():
        out[field] = list(by_value.values())
    return out


# ✅ supports dict history + pydantic history safely
def _get_text_from_msg(msg: Any) -> str:
    """
    Supports:
      - dict: {"text": "..."}
      - pydantic: msg.text
    """
    if isinstance(msg, dict):
        return msg.get("text", "") or ""
    return getattr(msg, "text", "") or ""


def aggregate_evidence_from_history(history, current_text: str):
    evidence_map: Dict[str, Dict[str, Any]] = {}

    # history
    for i, msg in enumerate(history or []):
        turn = i + 1
        f = extract_features(_get_text_from_msg(msg))

        _add_evidence(evidence_map, "upiIds", f.get("upiIds", []), turn)
        _add_evidence(evidence_map, "bankAccounts", f.get("bankAccounts", []), turn)
        _add_evidence(evidence_map, "ifscCodes", f.get("ifscCodes", []), turn)
        _add_evidence(evidence_map, "phishingLinks", f.get("phishingLinks", []), turn)
        _add_evidence(evidence_map, "phoneNumbers", f.get("phoneNumbers", []), turn)
        _add_evidence(evidence_map, "emailIds", f.get("emailIds", []), turn)

    # current message
    current_turn = (len(history or []) + 1)
    now_f = extract_features(current_text)

    links_conf = 0.92 if any(
        str(l).lower().startswith("upi://pay") for l in (now_f.get("phishingLinks") or [])
    ) else None

    _add_evidence(evidence_map, "upiIds", now_f.get("upiIds", []), current_turn)
    _add_evidence(evidence_map, "bankAccounts", now_f.get("bankAccounts", []), current_turn)
    _add_evidence(evidence_map, "ifscCodes", now_f.get("ifscCodes", []), current_turn)
    _add_evidence(
        evidence_map,
        "phishingLinks",
        now_f.get("phishingLinks", []),
        current_turn,
        confidence_override=links_conf
    )
    _add_evidence(evidence_map, "phoneNumbers", now_f.get("phoneNumbers", []), current_turn)
    _add_evidence(evidence_map, "emailIds", now_f.get("emailIds", []), current_turn)

    # behavioral signals (simple OR)
    has_qr = False
    has_pay = False
    for msg in history or []:
        f = extract_features(_get_text_from_msg(msg))
        has_qr = has_qr or bool(f.get("hasQRIntent", False))
        has_pay = has_pay or bool(f.get("hasPaymentIntent", False))

    has_qr = has_qr or bool(now_f.get("hasQRIntent", False))
    has_pay = has_pay or bool(now_f.get("hasPaymentIntent", False))

    evidence = _finalize_evidence(evidence_map)
    evidence["hasQRIntent"] = has_qr
    evidence["hasPaymentIntent"] = has_pay

    return evidence


# -----------------------------
# ✅ Stable threatClusterId from cumulative evidence
# -----------------------------
def _values_from_evidence(items: Any) -> List[str]:
    """
    Accepts:
      - [{"value": "...", ...}, ...]
      - ["...", ...]
    Returns list[str]
    """
    if not items:
        return []
    out: List[str] = []
    if isinstance(items, list):
        for x in items:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict) and "value" in x:
                out.append(str(x["value"]))
    return [v.strip().lower() for v in out if v and str(v).strip()]


def compute_threat_cluster_id(final_intel: Dict[str, Any]) -> Optional[str]:
    """
    Stable across turns: uses cumulative evidence, not just current message.
    """
    if not final_intel:
        return None

    items: List[str] = []
    items += _values_from_evidence(final_intel.get("upiIds"))
    items += _values_from_evidence(final_intel.get("phishingLinks"))
    items += _values_from_evidence(final_intel.get("phoneNumbers"))
    items += _values_from_evidence(final_intel.get("emailIds"))
    items += _values_from_evidence(final_intel.get("bankAccounts"))
    items += _values_from_evidence(final_intel.get("ifscCodes"))

    items = [x for x in items if x]
    if not items:
        return None

    raw = "|".join(sorted(set(items)))
    return "cluster_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]


# -----------------------------
# ✅ GUVI CALLBACK HELPERS
# -----------------------------
def _flatten_evidence_values(items: Any) -> List[str]:
    """
    Converts evidence lists into plain list[str] for GUVI payload.
    Supports:
      - [{"value": "...", ...}, ...]
      - ["...", ...]
    """
    if not items:
        return []
    out: List[str] = []
    if isinstance(items, list):
        for x in items:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict) and "value" in x:
                out.append(str(x["value"]))
    return list(dict.fromkeys([v for v in out if v and str(v).strip()]))


def _has_any_actionable_intel(final_intel: Dict[str, Any]) -> bool:
    if not final_intel:
        return False
    keys = ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "emailIds", "ifscCodes"]
    for k in keys:
        if _flatten_evidence_values(final_intel.get(k)):
            return True
    return False


def _build_guvi_payload(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    final_intel: Dict[str, Any],
    suspicious_keywords: List[str],
    agent_notes: str
) -> Dict[str, Any]:
    return {
        "sessionId": session_id,
        "scamDetected": bool(scam_detected),
        "totalMessagesExchanged": int(total_messages),
        "extractedIntelligence": {
            "bankAccounts": _flatten_evidence_values(final_intel.get("bankAccounts")),
            "upiIds": _flatten_evidence_values(final_intel.get("upiIds")),
            "phishingLinks": _flatten_evidence_values(final_intel.get("phishingLinks")),
            "phoneNumbers": _flatten_evidence_values(final_intel.get("phoneNumbers")),
            "suspiciousKeywords": list(dict.fromkeys([k for k in (suspicious_keywords or []) if k]))
        },
        "agentNotes": agent_notes
    }


def _send_guvi_callback(payload: Dict[str, Any], timeout_sec: int = 6) -> Dict[str, Any]:
    """
    Returns:
      {"ok": True/False, "status_code": int|None, "error": str|None}
    """
    try:
        resp = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=timeout_sec)
        ok = 200 <= resp.status_code < 300
        return {"ok": ok, "status_code": resp.status_code, "error": None if ok else resp.text[:300]}
    except Exception as e:
        return {"ok": False, "status_code": None, "error": str(e)[:300]}


@app.get("/")
def root():
    return {"status": "Agentic Honeypot API is running"}


@app.get("/health")
def health():
    return {"ok": True}


# ✅ GET /honeypot for Endpoint Tester compatibility (prevents 405)
@app.get("/honeypot")
def honeypot_get(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return {"ok": True, "message": "Honeypot endpoint reachable"}


@app.post("/honeypot")
def receive_message(
    data: IncomingMessage,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    now = time.time()

    # server-side store
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "startedAt": now,
            "lastSeenAt": now,
            "turns": 0,
            "history": [],
            "threatClusterId": None,
            # callback state
            "callbackSent": False,
            "callbackResult": None,
            "callbackSentAt": None
        }
    else:
        SESSION_STORE[session_id]["lastSeenAt"] = now

    server_history = SESSION_STORE[session_id]["history"]

    # true turn index from server history
    current_turn = len(server_history) + 1
    SESSION_STORE[session_id]["turns"] = current_turn

    # detection uses SERVER history
    detection = detect_scam(data.message.text, server_history)

    # cumulative evidence uses SERVER history
    final_intel = aggregate_evidence_from_history(server_history, data.message.text)

    # stable cluster id set once
    existing_cluster_id = SESSION_STORE[session_id].get("threatClusterId")
    computed_cluster_id = compute_threat_cluster_id(final_intel)
    if existing_cluster_id is None and computed_cluster_id is not None:
        SESSION_STORE[session_id]["threatClusterId"] = computed_cluster_id
    stable_cluster_id = SESSION_STORE[session_id]["threatClusterId"]

    # agent
    agent_result = agent_decision(
        detection,
        conversation_history=server_history,
        extracted_intelligence=final_intel
    )

    # append message AFTER processing
    server_history.append({
        "sender": data.message.sender,
        "text": data.message.text,
        "timestamp": data.message.timestamp.isoformat() if hasattr(data.message.timestamp, "isoformat") else str(data.message.timestamp)
    })

    duration_sec = int(now - SESSION_STORE[session_id]["startedAt"])
    conversation_turns = current_turn
    total_messages_exchanged = current_turn  # server-based count

    # -----------------------------
    # ✅ GUVI CALLBACK (mandatory)
    # -----------------------------
    metadata = data.metadata or {}
    finalize_flag = bool(
        metadata.get("finalize") or
        metadata.get("isFinal") or
        metadata.get("endConversation") or
        metadata.get("conversationEnded")
    )

    has_intel = _has_any_actionable_intel(final_intel)
    should_send_callback = (
        detection.get("scamDetected", False)
        and not SESSION_STORE[session_id].get("callbackSent", False)
        and (
            finalize_flag
            or (has_intel and conversation_turns >= 2)
            or (conversation_turns >= 6)
        )
    )

    callback_status = None
    if should_send_callback:
        suspicious_keywords = (detection.get("indicators", {}) or {}).get("keywords", []) or []
        agent_notes = (
            f"Stage={detection.get('scamStage')} Type={detection.get('scamType')}. "
            f"AgentMode={agent_result.get('agentMode')} Action={agent_result.get('action')}. "
            f"CollectedIntel={('yes' if has_intel else 'no')}."
        )

        payload = _build_guvi_payload(
            session_id=session_id,
            scam_detected=True,
            total_messages=total_messages_exchanged,
            final_intel=final_intel,
            suspicious_keywords=suspicious_keywords,
            agent_notes=agent_notes
        )

        callback_status = _send_guvi_callback(payload)
        SESSION_STORE[session_id]["callbackSent"] = bool(callback_status.get("ok"))
        SESSION_STORE[session_id]["callbackResult"] = callback_status
        SESSION_STORE[session_id]["callbackSentAt"] = int(time.time())

    # If already sent earlier, surface the last result (optional)
    if callback_status is None and SESSION_STORE[session_id].get("callbackResult"):
        callback_status = SESSION_STORE[session_id]["callbackResult"]

    # ---------------------------------------------------------
    # ✅ FINAL FIX FOR GUVI TESTER:
    # Return ONLY the minimal expected response format.
    # ---------------------------------------------------------
    reply_text = agent_result.get("agentReply") or "Why is my account being suspended?"
    return {
        "status": "success",
        "reply": reply_text
    }