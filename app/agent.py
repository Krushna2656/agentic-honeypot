import random
from typing import Dict, Any, Optional, List

# -----------------------------
# Persona (believable human)
# -----------------------------
PERSONA = {
    "name": "Rahul",
    "style": "non-technical, polite, slightly anxious, cooperative",
    "constraints": [
        "Never reveal scam detection.",
        "Never accuse or threaten.",
        "Ask for one detail at a time.",
        "Sound natural and human.",
        "Keep messages short (1-2 lines)."
    ]
}


def _pick(options: List[str]) -> str:
    return random.choice(options)


def _normalize_list(items):
    """
    items can be:
      - ["verify@upi"]
      - [{"value":"verify@upi","confidence":0.92,"sourceTurn":1}]
    We normalize to list[str] of values only.
    """
    out = []
    for it in items or []:
        if isinstance(it, dict) and "value" in it:
            out.append(it["value"])
        elif isinstance(it, str):
            out.append(it)
    return out


def _intel_gaps(extracted: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    extracted = extracted or {}

    upi = _normalize_list(extracted.get("upiIds"))
    banks = _normalize_list(extracted.get("bankAccounts"))
    ifsc = _normalize_list(extracted.get("ifscCodes"))
    links = _normalize_list(extracted.get("phishingLinks") or extracted.get("links"))
    phones = _normalize_list(extracted.get("phoneNumbers"))
    emails = _normalize_list(extracted.get("emailIds"))

    return {
        "need_upi": len(upi) == 0,
        "need_bank": len(banks) == 0,
        "need_ifsc": len(ifsc) == 0,
        "need_link": len(links) == 0,
        "need_phone": len(phones) == 0,
        "need_email": len(emails) == 0,
    }


def generate_reply(
    mode: str,
    stage: Optional[str] = None,
    scam_type: Optional[str] = None,
    extracted: Optional[Dict[str, Any]] = None
) -> Dict[str, str]:
    stage = (stage or "UNKNOWN").upper()
    scam_type = (scam_type or "UNKNOWN").upper()
    extracted = extracted or {}

    gaps = _intel_gaps(extracted)
    has_payment_intent = bool(extracted.get("hasPaymentIntent", False))
    has_qr_intent = bool(extracted.get("hasQRIntent", False))

    soft_openers = [
        "I’m a bit confused. Can you explain what I need to do?",
        "Okay… what exactly is the issue with my account?",
        "I don’t understand this. What should I do step by step?"
    ]

    ask_upi = [
        "Which exact UPI ID should I use? Please send it again.",
        "Can you share the UPI handle (like name@bank) so I don’t type wrong?",
        "What’s the UPI ID and receiver name? I want to confirm before paying."
    ]

    ask_link = [
        "Can you send the official verification link again? The page didn’t open.",
        "Please share the exact link. I want to make sure I’m on the right site.",
        "The link isn’t loading—send the correct URL once more."
    ]

    ask_bank = [
        "If UPI isn’t working, can you share bank details (A/C + IFSC + name)?",
        "Please send the account number and IFSC—my app asks for those.",
        "Can you share beneficiary bank details so I can complete verification?"
    ]

    ask_ifsc_only = [
        "IFSC code bhi bhej do please. App IFSC maang raha hai.",
        "Receiver bank ka IFSC kya hai? Without IFSC it’s not allowing."
    ]

    ask_receiver_or_collect = [
        "Receiver name kya aayega? (UPI pe jo name show hota hai) I want to confirm.",
        "Can you send a collect request? I’m not able to type the UPI ID correctly.",
        "If this UPI fails, do you have another UPI ID I can try?"
    ]

    # ✅ Best phishing follow-up: contact details (more realistic than bank)
    ask_support_contact = [
        "Aapka support number kya hai? Call karke confirm karna hai.",
        "Official email ID bhej do, main wahi pe forward karke verify karunga.",
        "Ticket/reference number kya hai? Without that I can’t proceed."
    ]

    # Stage-based base prompts
    stage_prompts = {
        "RECON": [
            "Hi, yes—what is this about?",
            "Hello. Which service are you calling from?"
        ],
        "SOCIAL_ENGINEERING": [
            "I’m worried now. What verification is needed?",
            "Why is my account suspended? I didn’t do anything."
        ],
        "URGENCY": [
            "Okay okay, I don’t want it blocked. What do I do now?",
            "Please guide quickly. I’m not technical."
        ],
        "PAYMENT_REQUEST": [
            "You’re asking payment… I need exact details so I don’t make a mistake.",
            "I can do it, but tell me the exact ID/link."
        ],
        "PHISHING": [
            "I clicked but it looks different.",
            "The site is asking too many things."
        ],
        "OTP_FRAUD": [
            "OTP? But why OTP is needed for this?",
            "I got OTP, but I’m scared to share. What is it for?"
        ],
        "REWARD_LURE": [
            "Really? What do I need to do to claim it?",
            "Okay… what’s the process for the reward?"
        ],
        "UNKNOWN": [
            "Can you clarify what you need from me?",
            "What is this regarding? Please explain."
        ]
    }

    base = _pick(stage_prompts.get(stage, stage_prompts["UNKNOWN"]))

    # ------------------ SOFT MODE ------------------
    if mode == "SOFT_ENGAGEMENT":
        reply = _pick([base] + soft_openers)
        return {
            "agentReply": reply,
            "agentGoal": "Keep scammer engaged and gather more signals without exposure."
        }

    # ------------------ INTEL MODE ------------------
    if mode == "INTELLIGENCE_EXTRACTION":

        # Priority 1: Get link if missing (only when stage suggests link scams)
        if gaps["need_link"] and stage in ["PHISHING", "SOCIAL_ENGINEERING", "URGENCY"]:
            return {"agentReply": _pick(ask_link), "agentGoal": "Extract phishing URL for reporting."}

        # ✅ If phishing link already exists → ask contact / ticket (more realistic)
        if stage == "PHISHING" and (not gaps["need_link"]):
            return {"agentReply": _pick(ask_support_contact), "agentGoal": "Extract official contact details for intelligence."}

        # Priority 2: Payment/UPI details
        if gaps["need_upi"] and (has_payment_intent or stage in ["PAYMENT_REQUEST", "URGENCY", "SOCIAL_ENGINEERING"]):
            return {"agentReply": _pick(ask_upi), "agentGoal": "Extract UPI ID / receiver handle."}

        # If QR intent -> ask for QR / collect request
        if has_qr_intent and (not gaps["need_upi"]):
            return {"agentReply": _pick(ask_receiver_or_collect), "agentGoal": "Extend conversation using QR/collect flow."}

        # Priority 3: Bank details
        if gaps["need_bank"]:
            return {"agentReply": _pick(ask_bank), "agentGoal": "Extract bank account details."}

        # If bank exists but IFSC missing
        if (not gaps["need_bank"]) and gaps["need_ifsc"]:
            return {"agentReply": _pick(ask_ifsc_only), "agentGoal": "Extract IFSC to complete bank intelligence."}

        followups = [
            "Okay, I noted that. What’s the next step?",
            "Done. If it fails again, what should I do?",
            "Can you confirm receiver name once more?"
        ]
        return {"agentReply": _pick(followups), "agentGoal": "Keep conversation alive for more evidence."}

    return {"agentReply": None, "agentGoal": "No action needed."}


def agent_decision(
    analysis: dict,
    conversation_history: Optional[list] = None,
    extracted_intelligence: Optional[dict] = None
) -> Dict[str, Any]:

    if not analysis.get("scamDetected", False):
        return {
            "activated": False,
            "riskLevel": "LOW",
            "action": "ALLOW",
            "agentMode": "PASSIVE",
            "message": "No scam indicators detected",
            "agentReply": None,
            "agentGoal": "No action needed."
        }

    score = float(analysis.get("confidenceScore", 0.0))
    scam_type = analysis.get("scamType")
    stage = analysis.get("scamStage")

    # HIGH: intelligence extraction
    if score >= 0.8:
        reply_pack = generate_reply(
            mode="INTELLIGENCE_EXTRACTION",
            stage=stage,
            scam_type=scam_type,
            extracted=extracted_intelligence
        )
        return {
            "activated": True,
            "riskLevel": "HIGH",
            "action": "ENGAGE",
            "agentMode": "INTELLIGENCE_EXTRACTION",
            "message": f"High confidence {scam_type} detected at {stage} stage",
            "agentReply": reply_pack["agentReply"],
            "agentGoal": reply_pack["agentGoal"],
            "persona": PERSONA["style"]
        }

    # MEDIUM: soft engagement
    if score >= 0.5:
        reply_pack = generate_reply(
            mode="SOFT_ENGAGEMENT",
            stage=stage,
            scam_type=scam_type,
            extracted=extracted_intelligence
        )
        return {
            "activated": True,
            "riskLevel": "MEDIUM",
            "action": "MONITOR",
            "agentMode": "SOFT_ENGAGEMENT",
            "message": f"Possible {scam_type}. Monitoring conversation",
            "agentReply": reply_pack["agentReply"],
            "agentGoal": reply_pack["agentGoal"],
            "persona": PERSONA["style"]
        }

    return {
        "activated": False,
        "riskLevel": "LOW",
        "action": "MONITOR",
        "agentMode": "PASSIVE",
        "message": "Suspicious but not confirmed",
        "agentReply": None,
        "agentGoal": "Wait for more signals."
    }
