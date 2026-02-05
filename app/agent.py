import random
from typing import Dict, Any, Optional, List

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


def _values_only(items: Any) -> List[str]:
    """
    Supports BOTH formats:
      - ["verify@upi"]
      - [{"value":"verify@upi","confidence":0.92,"sourceTurn":1}]
    """
    if not items:
        return []
    if isinstance(items, list):
        out = []
        for x in items:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict) and "value" in x:
                out.append(str(x["value"]))
        return [v for v in out if v and str(v).strip()]
    return []


def _intel_gaps(extracted: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    extracted = extracted or {}

    upi = _values_only(extracted.get("upiIds"))
    banks = _values_only(extracted.get("bankAccounts"))
    ifsc = _values_only(extracted.get("ifscCodes"))
    links = _values_only(extracted.get("phishingLinks")) or _values_only(extracted.get("links"))
    phones = _values_only(extracted.get("phoneNumbers"))
    emails = _values_only(extracted.get("emailIds"))

    has_any_strong = (len(upi) > 0) or (len(banks) > 0) or (len(ifsc) > 0) or (len(links) > 0)

    return {
        "need_upi": len(upi) == 0,
        "need_bank": len(banks) == 0,
        "need_ifsc": len(ifsc) == 0,
        "need_link": len(links) == 0,
        "need_phone": len(phones) == 0,
        "need_email": len(emails) == 0,
        "has_link": len(links) > 0,
        "has_upi": len(upi) > 0,
        "has_any_strong": has_any_strong,
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

    ask_link = [
        "Can you send the official verification link again? The page didn’t open.",
        "Please share the exact link. I want to make sure I’m on the right site.",
        "The link isn’t loading—send the correct URL once more."
    ]

    phishing_followup = [
        "I opened it. It’s asking for details—what exactly should I fill?",
        "The page looks different. Which option should I click?",
        "It’s asking for OTP/UPI PIN—are you sure this is required?"
    ]

    ask_upi = [
        "Which exact UPI ID should I use? Please send it again.",
        "Can you share the UPI handle (like name@bank) so I don’t type wrong?",
        "What’s the UPI ID and receiver name? I want to confirm before paying."
    ]

    ask_receiver_or_collect = [
        "Receiver name kya aayega? (UPI pe jo name show hota hai) I want to confirm.",
        "Can you send a collect request? I’m not able to type the UPI ID correctly.",
        "If this UPI fails, do you have another UPI ID I can try?"
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

    ask_contact_details = [
        "Aapka support number kya hai? Call karke confirm karna hai.",
        "Official email ID bhej do, I’ll forward screenshot there."
    ]

    phishing_payment_followup = [
        "UPI me receiver name kya dikh raha hai? I want to confirm before paying.",
        "Payment fail ho gaya to kya bank transfer karna hai? Account + IFSC bhej do.",
        "Amount kitna exactly dalna hai? And receiver name confirm kar do."
    ]

    stage_prompts = {
        "RECON": ["Hi, yes—what is this about?", "Hello. Which service are you calling from?"],
        "SOCIAL_ENGINEERING": ["I’m worried now. What verification is needed?", "Why is my account suspended? I didn’t do anything."],
        "URGENCY": ["Okay okay, I don’t want it blocked. What do I do now?", "Please guide quickly. I’m not technical."],
        "PAYMENT_REQUEST": ["You’re asking payment… I need exact details so I don’t make a mistake.", "I can do it, but tell me the exact ID/link."],
        "PHISHING": ["I clicked but it looks different.", "The site is asking too many things."],
        "OTP_FRAUD": ["OTP? But why OTP is needed for this?", "I got OTP, but I’m scared to share. What is it for?"],
        "REWARD_LURE": ["Really? What do I need to do to claim it?", "Okay… what’s the process for the reward?"],
        "UNKNOWN": ["Can you clarify what you need from me?", "What is this regarding? Please explain."]
    }

    base = _pick(stage_prompts.get(stage, stage_prompts["UNKNOWN"]))

    if mode == "SOFT_ENGAGEMENT":
        reply = _pick([base] + soft_openers)
        return {"agentReply": reply, "agentGoal": "Keep scammer engaged and gather more signals without exposure."}

    if mode == "INTELLIGENCE_EXTRACTION":

        if stage == "PHISHING":
            if gaps["need_link"]:
                return {"agentReply": _pick(ask_link), "agentGoal": "Extract phishing URL for reporting."}

            if gaps["has_upi"] or has_payment_intent:
                return {"agentReply": _pick(phishing_payment_followup), "agentGoal": "Continue extraction by moving phishing into payment flow (receiver/bank details)."}

            return {"agentReply": _pick(phishing_followup), "agentGoal": "Keep phishing engagement realistic and gather next-step instructions."}

        if gaps["need_link"] and stage in ["SOCIAL_ENGINEERING", "URGENCY"]:
            return {"agentReply": _pick(ask_link), "agentGoal": "Extract phishing URL for reporting."}

        if gaps["need_upi"] and (has_payment_intent or stage == "PAYMENT_REQUEST"):
            return {"agentReply": _pick(ask_upi), "agentGoal": "Extract UPI ID / receiver handle."}

        if has_qr_intent and (not gaps["need_upi"]):
            return {"agentReply": _pick(ask_receiver_or_collect), "agentGoal": "Extend conversation using QR/collect flow."}

        if gaps["need_bank"]:
            return {"agentReply": _pick(ask_bank), "agentGoal": "Extract bank account details."}

        if (not gaps["need_bank"]) and gaps["need_ifsc"]:
            return {"agentReply": _pick(ask_ifsc_only), "agentGoal": "Extract IFSC to complete bank intelligence."}

        if gaps["need_phone"] or gaps["need_email"]:
            return {"agentReply": _pick(ask_contact_details), "agentGoal": "Extract official contact details for intelligence."}

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

    extracted_intelligence = extracted_intelligence or {}
    gaps = _intel_gaps(extracted_intelligence)

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

    evidence_lock = (
        gaps["has_any_strong"]
        or bool(extracted_intelligence.get("hasPaymentIntent"))
        or bool(extracted_intelligence.get("hasQRIntent"))
    )

    if score >= 0.8:
        reply_pack = generate_reply("INTELLIGENCE_EXTRACTION", stage, scam_type, extracted_intelligence)
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

    if score >= 0.5 and evidence_lock:
        reply_pack = generate_reply("INTELLIGENCE_EXTRACTION", stage, scam_type, extracted_intelligence)
        return {
            "activated": True,
            "riskLevel": "HIGH",
            "action": "ENGAGE",
            "agentMode": "INTELLIGENCE_EXTRACTION",
            "message": f"Evidence present. Continuing extraction for {scam_type}.",
            "agentReply": reply_pack["agentReply"],
            "agentGoal": reply_pack["agentGoal"],
            "persona": PERSONA["style"]
        }

    if score >= 0.5:
        reply_pack = generate_reply("SOFT_ENGAGEMENT", stage, scam_type, extracted_intelligence)
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