import os
import time
import hashlib
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Header, HTTPException
from app.schemas import IncomingMessage
from app.detector import detect_scam
from app.extractor import extract_features
from app.agent import agent_decision

app = FastAPI(title="Agentic Honeypot API")

# ✅ API KEY: ENV first, fallback local
API_KEY = os.getenv("HONEYPOT_API_KEY", "Honeypot2026@Krushna")

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


def aggregate_evidence_from_history(history, current_text: str):
    evidence_map: Dict[str, Dict[str, Any]] = {}

    # history
    for i, msg in enumerate(history or []):
        turn = i + 1
        f = extract_features(getattr(msg, "text", ""))

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
    _add_evidence(evidence_map, "phishingLinks", now_f.get("phishingLinks", []), current_turn, confidence_override=links_conf)
    _add_evidence(evidence_map, "phoneNumbers", now_f.get("phoneNumbers", []), current_turn)
    _add_evidence(evidence_map, "emailIds", now_f.get("emailIds", []), current_turn)

    # behavioral signals (simple OR)
    has_qr = False
    has_pay = False
    for msg in history or []:
        f = extract_features(getattr(msg, "text", ""))
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


@app.get("/")
def root():
    return {"status": "Agentic Honeypot API is running"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/honeypot")
def receive_message(
    data: IncomingMessage,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    now = time.time()

    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {"startedAt": now, "lastSeenAt": now, "turns": 0}
    else:
        SESSION_STORE[session_id]["lastSeenAt"] = now

    SESSION_STORE[session_id]["turns"] += 1

    # 1) detection (rule engine)
    detection = detect_scam(data.message.text, data.conversationHistory)

    # 2) cumulative evidence
    final_intel = aggregate_evidence_from_history(data.conversationHistory, data.message.text)

    # ✅ stable cluster id from cumulative intel
    stable_cluster_id = compute_threat_cluster_id(final_intel)

    # 3) agent
    agent_result = agent_decision(
        detection,
        conversation_history=data.conversationHistory,
        extracted_intelligence=final_intel
    )

    duration_sec = int(now - SESSION_STORE[session_id]["startedAt"])
    conversation_turns = max(SESSION_STORE[session_id]["turns"], len(data.conversationHistory) + 1)

    return {
        "sessionId": data.sessionId,

        "scamDetection": {
            "scamDetected": detection["scamDetected"],
            "confidenceScore": detection["confidenceScore"],
            "scamStage": detection["scamStage"],
            "scamType": detection["scamType"]
        },

        # ✅ stable across turns (best for judges)
        "threatClusterId": stable_cluster_id,

        "agentStatus": {
            "activated": agent_result.get("activated", agent_result.get("agentMode") != "PASSIVE"),
            "riskLevel": agent_result["riskLevel"],
            "action": agent_result["action"],
            "agentMode": agent_result["agentMode"],
            "persona": agent_result.get("persona")
        },

        "agentReply": agent_result.get("agentReply"),
        "agentGoal": agent_result.get("agentGoal"),

        "engagementMetrics": {
            "conversationTurns": conversation_turns,
            "engagementDurationSeconds": duration_sec
        },

        "extractedIntelligence": final_intel
    }
