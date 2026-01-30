import os
import time
from typing import Dict, Any

from fastapi import FastAPI, Header, HTTPException
from app.schemas import IncomingMessage
from app.detector import detect_scam
from app.extractor import extract_features
from app.agent import agent_decision

app = FastAPI(title="Agentic Honeypot API")

# ✅ API KEY: ENV first, fallback local
# Render env var name: HONEYPOT_API_KEY
API_KEY = os.getenv("HONEYPOT_API_KEY", "Honeypot2026@Krushna")

# -----------------------------
# Simple in-memory session store
# (Works great for hackathon eval)
# -----------------------------
SESSION_STORE: Dict[str, Dict[str, Any]] = {}


# -----------------------------
# Helpers: Multi-turn aggregation
# -----------------------------
def merge_unique(a, b):
    """Merge two lists, keep order, remove duplicates."""
    return list(dict.fromkeys((a or []) + (b or [])))


def aggregate_from_history(history):
    """
    Extract intelligence from conversation history and aggregate it.
    This prevents intelligence from 'resetting' each turn.
    """
    agg = {
        "upiIds": [],
        "bankAccounts": [],
        "ifscCodes": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "emailIds": [],
        "hasQRIntent": False,
        "hasPaymentIntent": False
    }

    for msg in history or []:
        f = extract_features(getattr(msg, "text", ""))

        agg["upiIds"] = merge_unique(agg["upiIds"], f.get("upiIds"))
        agg["bankAccounts"] = merge_unique(agg["bankAccounts"], f.get("bankAccounts"))
        agg["ifscCodes"] = merge_unique(agg["ifscCodes"], f.get("ifscCodes"))
        agg["phishingLinks"] = merge_unique(agg["phishingLinks"], f.get("phishingLinks"))
        agg["phoneNumbers"] = merge_unique(agg["phoneNumbers"], f.get("phoneNumbers"))
        agg["emailIds"] = merge_unique(agg["emailIds"], f.get("emailIds"))

        agg["hasQRIntent"] = agg["hasQRIntent"] or bool(f.get("hasQRIntent", False))
        agg["hasPaymentIntent"] = agg["hasPaymentIntent"] or bool(f.get("hasPaymentIntent", False))

    return agg


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
    # -----------------------------
    # API Key Security
    # -----------------------------
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # -----------------------------
    # Session timing (cumulative)
    # -----------------------------
    session_id = data.sessionId
    now = time.time()

    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "startedAt": now,
            "lastSeenAt": now,
            "turns": 0
        }
    else:
        SESSION_STORE[session_id]["lastSeenAt"] = now

    # We count a "turn" per incoming message event
    SESSION_STORE[session_id]["turns"] += 1

    # -----------------------------
    # 1) Scam Detection
    # -----------------------------
    detection = detect_scam(
        data.message.text,
        data.conversationHistory
    )

    # -----------------------------
    # 2) Intelligence Extraction (current message + history)
    # -----------------------------
    extracted_now = extract_features(data.message.text)
    extracted_history = aggregate_from_history(data.conversationHistory)

    # Final (cumulative) intelligence
    final_intel = {
        "upiIds": merge_unique(extracted_history["upiIds"], extracted_now.get("upiIds")),
        "bankAccounts": merge_unique(extracted_history["bankAccounts"], extracted_now.get("bankAccounts")),
        "ifscCodes": merge_unique(extracted_history["ifscCodes"], extracted_now.get("ifscCodes")),
        "phishingLinks": merge_unique(extracted_history["phishingLinks"], extracted_now.get("phishingLinks")),
        "phoneNumbers": merge_unique(extracted_history["phoneNumbers"], extracted_now.get("phoneNumbers")),
        "emailIds": merge_unique(extracted_history["emailIds"], extracted_now.get("emailIds")),
        "hasQRIntent": bool(extracted_history.get("hasQRIntent")) or bool(extracted_now.get("hasQRIntent", False)),
        "hasPaymentIntent": bool(extracted_history.get("hasPaymentIntent")) or bool(extracted_now.get("hasPaymentIntent", False))
    }

    # -----------------------------
    # 3) Agent Handoff (Autonomous)
    # Pass cumulative intel + history for smarter strategy
    # -----------------------------
    agent_result = agent_decision(
        detection,
        conversation_history=data.conversationHistory,
        extracted_intelligence=final_intel
    )

    # -----------------------------
    # Engagement metrics
    # -----------------------------
    duration_sec = int(now - SESSION_STORE[session_id]["startedAt"])

    # Prefer event turns (store) over just history length (history may be limited)
    conversation_turns = max(
        SESSION_STORE[session_id]["turns"],
        len(data.conversationHistory) + 1
    )

    # -----------------------------
    # Judge-ready structured output
    # -----------------------------
    return {
        "sessionId": data.sessionId,

        "scamDetection": {
            "scamDetected": detection["scamDetected"],
            "confidenceScore": detection["confidenceScore"],
            "scamStage": detection["scamStage"],
            "scamType": detection["scamType"]
        },

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

        # ✅ cumulative intelligence (history + current)
        "extractedIntelligence": final_intel
    }
