import time
from fastapi import FastAPI, Header, HTTPException
from app.schemas import IncomingMessage
from app.detector import detect_scam
from app.extractor import extract_features
from app.agent import agent_decision

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "Demo_1234"


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
        "emailIds": []
    }

    for msg in history or []:
        f = extract_features(getattr(msg, "text", ""))

        agg["upiIds"] = merge_unique(agg["upiIds"], f.get("upiIds"))
        agg["bankAccounts"] = merge_unique(agg["bankAccounts"], f.get("bankAccounts"))
        agg["ifscCodes"] = merge_unique(agg["ifscCodes"], f.get("ifscCodes"))
        agg["phishingLinks"] = merge_unique(agg["phishingLinks"], f.get("phishingLinks"))
        agg["phoneNumbers"] = merge_unique(agg["phoneNumbers"], f.get("phoneNumbers"))
        agg["emailIds"] = merge_unique(agg["emailIds"], f.get("emailIds"))

    return agg


@app.get("/")
def root():
    return {"status": "Agentic Honeypot API is running"}


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

    start_time = time.time()

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
        "hasQRIntent": extracted_now.get("hasQRIntent", False),
        "hasPaymentIntent": extracted_now.get("hasPaymentIntent", False)
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

    end_time = time.time()

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
            "conversationTurns": len(data.conversationHistory) + 1,
            "engagementDurationSeconds": int(end_time - start_time)
        },

        # ✅ cumulative intelligence (history + current)
        "extractedIntelligence": final_intel
    }
