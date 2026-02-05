import random
import hashlib
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


def _make_rng(session_id: Optional[str], mode: str, stage: str, turn_index: int) -> random.Random:
    """
    Deterministic RNG:
    same (sessionId + mode + stage + turn) => same reply choice.
    Helps judge testing (stable outputs across reruns).
    """
    key = f"{session_id or 'no_session'}|{mode}|{stage}|{turn_index}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()
    seed_int = int(h[:16], 16)  # enough bits
    return random.Random(seed_int)


def _pick(options: List[str], rng: Optional[random.Random] = None) -> str:
    if not options:
        return ""
    if rng is None:
        return random.choice(options)
    return rng.choice(options)


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

    has_link = len(links) > 0
    has_upi = len(upi) > 0
    has_bank = len(banks) > 0
    has_ifsc = len(ifsc) > 0

    has_any_strong = has_upi or has_bank or has_ifsc or has_link

    return {
        "need_upi": not has_upi,
        "need_bank": not has_bank,
        "need_ifsc": not has_ifsc,
        "need_link": not has_link,
        "need_phone": len(phones) == 0,
        "need_email": len(emails) == 0,
        "has_link": has_link,
        "has_upi": has_upi,
        "has_bank": has_bank,
        "has_ifsc": has_ifsc,
        "has_any_strong": has_any_strong,
    }


def generate_reply(
    mode: str,
    stage: Optional[str] = None,
    scam_type: Optional[str] = None,
    extracted: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    turn_index: int = 1
) -> Dict[str, str]:
    stage = (stage or "UNKNOWN").upper()
    scam_type = (scam_type or "UNKNOWN").upper()
    extracted = extracted or {}

    rng = _make_rng(session_id, mode, stage, turn_index)

    gaps = _intel_gaps(extracted)
    has_payment_intent = bool(extracted.get("hasPaymentIntent", False))
    has_qr_intent = bool(extracted.get("hasQRIntent", False))

    # -----------------------------
    # Safe benign-help replies (expanded)
    # -----------------------------
    benign_help = [
        "Aap kaunsa app use karte ho (GPay/PhonePe/Paytm)? Main safe steps bata deta hoon.",
        "UPI PIN reset ke liye app me ‘Forgot UPI PIN’ / ‘Reset PIN’ option hota hai—kaunsa app hai?",
        "PIN reset ke liye debit card details + OTP lagta hai. Aap kaunsa bank/app use kar rahe ho?",
        "Aapka issue exactly kya hai—payment fail, PIN issue, ya account warning?",
        "App me last 2-3 transactions dikh rahe hain kya? (Bas confirm karna hai.)"
    ]

    soft_openers = [
        "I’m a bit confused. Can you explain what I need to do?",
        "Okay… what exactly is the issue with my account?",
        "I don’t understand this. What should I do step by step?",
        "Wait—ye message kis number/email se aaya hai?",
        "Aap bol rahe ho verify… but verify kis cheez ka?"
    ]

    # -----------------------------
    # PHISHING / LINK (expanded)
    # -----------------------------
    ask_link = [
        "Can you send the official verification link again? The page didn’t open.",
        "Please share the exact link. I want to make sure I’m on the right site.",
        "The link isn’t loading—send the correct URL once more.",
        "Link open ho gaya, but address bar me exact URL kya dikh raha hai? Share karo please.",
        "Aap jo link bhej rahe ho, wahi official hai na? Ek baar full link paste kar do.",
        "Mere phone pe link broken aa raha hai—copy-paste karke dubara bhejo."
    ]

    phishing_followup = [
        "I opened it. It’s asking for details—what exactly should I fill?",
        "The page looks different. Which option should I click?",
        "It’s asking for OTP/UPI PIN—are you sure this is required?",
        "It’s asking for card details too… ye zaroori hai kya?",
        "It’s asking for netbanking/login—verification me login kyu chahiye?",
        "I see multiple buttons (Continue/Verify/Proceed). Kaunsa select karu?"
    ]

    # When phishing starts blending into payment flow
    phishing_payment_followup = [
        "UPI me receiver name kya dikh raha hai? I want to confirm before paying.",
        "Payment fail ho gaya to kya bank transfer karna hai? Account + IFSC bhej do.",
        "Amount kitna exactly dalna hai? And receiver name confirm kar do.",
        "App ‘collect request’ dikha raha hai—kya accept karna hai?",
        "Verification ke liye minimum kitna amount hai? Exact number bata do."
    ]

    # -----------------------------
    # UPI / PAYMENT (expanded)
    # -----------------------------
    ask_upi = [
        "Which exact UPI ID should I use? Please send it again.",
        "Can you share the UPI handle (like name@bank) so I don’t type wrong?",
        "What’s the UPI ID and receiver name? I want to confirm before paying.",
        "UPI ID me dot/underscore hai kya? Exact spelling bata do.",
        "Aapka UPI handle capital/small letters me farak padta hai kya? Exact share kar do.",
        "UPI ID ke saath receiver name bhi bata do—confirm karna hai."
    ]

    ask_receiver_or_collect = [
        "Receiver name kya aayega? (UPI pe jo name show hota hai) I want to confirm.",
        "Can you send a collect request? I’m not able to type the UPI ID correctly.",
        "If this UPI fails, do you have another UPI ID I can try?",
        "Collect request aayega to amount kitna rahega? Exact confirm kar do.",
        "Aapka UPI merchant hai ya personal? Name mismatch hua to kya karu?",
        "Mere app me ‘beneficiary pending’ dikh raha—kya accept karna hai?"
    ]

    # -----------------------------
    # BANK / IFSC (expanded)
    # -----------------------------
    ask_bank = [
        "If UPI isn’t working, can you share bank details (A/C + IFSC + name)?",
        "Please send the account number and IFSC—my app asks for those.",
        "Can you share beneficiary bank details so I can complete verification?",
        "NEFT/IMPS me beneficiary name mandatory hai—exact name kya hai?",
        "IMPS me branch details nahi maang rahe, bas A/C + IFSC chahiye—bhej do."
    ]

    ask_ifsc_only = [
        "IFSC code bhi bhej do please. App IFSC maang raha hai.",
        "Receiver bank ka IFSC kya hai? Without IFSC it’s not allowing.",
        "IFSC last 6 characters confirm kar do—galat hua to fail ho jata hai."
    ]

    bank_confirm = [
        "Thanks. Beneficiary name exactly kya hai? (bank me jo name show hota hai)",
        "Which bank/branch is this IFSC for? I want to confirm before transfer.",
        "Account type savings/current kya hai? Wrong type se fail ho jata hai.",
        "IMPS/NEFT me ‘beneficiary name mismatch’ aaya to kya karna hai?",
        "A/C number digits confirm kar do—9/12/16 digits? I want to avoid wrong transfer."
    ]

    # -----------------------------
    # CONTACT DETAILS (expanded)
    # -----------------------------
    ask_contact_details = [
        "Aapka support number kya hai? Call karke confirm karna hai.",
        "Official email ID bhej do, I’ll forward screenshot there.",
        "Aapka helpline number/extension kya hai? Main verify karke proceed karunga.",
        "Koi ticket/reference number hai? Main note kar leta hoon."
    ]

    # -----------------------------
    # ✅ OTP FRAUD — 12–15 unique replies + turn progression
    # Keep it OTP-only (no sharing), but gather intel: sender, sms text, purpose, channel, alt verification
    # -----------------------------
    otp_sender_bucket = [
        "Message me sender name kya dikh raha hai? Main confirm karna chahta hoon.",
        "OTP wale SMS me sender ID kya hai? (SBI/VM-… ) bas bata do.",
        "OTP message kis number/email se aaya? Exact sender batana.",
        "SMS me bank ka naam clear likha hai kya? Sender ID kya show ho raha hai?"
    ]

    otp_sms_text_bucket = [
        "OTP aaya hai—but SMS me exact line kya likhi hai? Copy karke bhejo.",
        "SMS me ‘for login’ ya ‘for payment’ aisa kuch likha hai kya? Exact words batao.",
        "OTP message me amount/merchant mention hai kya? Kya likha hai?",
        "OTP SMS me time/validity kitni likhi hai? 5 min/10 min?"
    ]

    otp_purpose_bucket = [
        "OTP share karna safe nahi lag raha. Ye login ka OTP hai ya payment ka?",
        "Ye OTP account access ke liye hai ya transaction confirm karne ke liye?",
        "Agar OTP login ka hua to risk hai—ye kis step pe generate hua hai?",
        "App me aapne kya action kiya jisse OTP aaya? Link open kiya ya payment click?"
    ]

    otp_safe_alt_bucket = [
        "Main OTP nahi share kar sakta—kya aap alternative verification (reference number) de sakte ho?",
        "OTP share nahi karunga—koi customer care number do, main call karke confirm kar leta hoon.",
        "Agar legit hai, to bank app me bhi alert aata hai—kya process ka reference ID hai?",
        "OTP ke bina koi verification step hai? Like registered email confirm ya ticket number?"
    ]

    otp_followup_fallback = [
        "Ek baar confirm: OTP kis service/app ke liye generate hua? (SBI YONO / netbanking / UPI?)",
        "OTP ke SMS me last 4 digits ya masked info aata hai kya? (Bas confirm karna.)",
        "OTP me kisi merchant ka naam dikh raha? Agar haan to kaunsa?"
    ]

    # Pick OTP reply bucket by turn (progression)
    def _otp_progressive_reply(ti: int) -> str:
        if ti <= 1:
            return _pick(otp_sender_bucket, rng)
        if ti == 2:
            return _pick(otp_sms_text_bucket, rng)
        if ti == 3:
            return _pick(otp_purpose_bucket, rng)
        if ti >= 4:
            # rotate between purpose and safe alternatives to keep convo alive
            buckets = otp_safe_alt_bucket + otp_purpose_bucket + otp_followup_fallback
            return _pick(buckets, rng)
        return _pick(otp_followup_fallback, rng)

    # -----------------------------
    # Stage prompts (expanded)
    # -----------------------------
    stage_prompts = {
        "RECON": [
            "Hi, yes—what is this about?",
            "Hello. Which service are you calling from?",
            "Haan bolo—kis kaam ke liye message kiya?"
        ],
        "SOCIAL_ENGINEERING": [
            "I’m worried now. What verification is needed?",
            "Why is my account suspended? I didn’t do anything.",
            "KYC pending ka matlab kya? Main kaunsa step miss kar gaya?",
            "Ye alert bank app me bhi dikh raha hai kya? Aap kya verify karwana chahte ho?"
        ],
        "URGENCY": [
            "Okay okay, I don’t want it blocked. What do I do now?",
            "Please guide quickly. I’m not technical.",
            "Thoda slow—main galti nahi karna chahta. Step-by-step bolo."
        ],
        "PAYMENT_REQUEST": [
            "You’re asking payment… I need exact details so I don’t make a mistake.",
            "I can do it, but tell me the exact ID/link.",
            "Payment karne se pehle receiver name confirm karna hai—kya dikhna chahiye?",
            "Amount exact kitna hai? Ek rupee bhi galat hua to fail ho jata."
        ],
        "PHISHING": [
            "I clicked but it looks different.",
            "The site is asking too many things.",
            "Page pe padlock/https nahi dikh raha—ye normal hai?"
        ],
        "OTP_FRAUD": [
            "OTP? But why OTP is needed for this?",
            "I got OTP, but I’m scared to share. What is it for?",
            "OTP share karna risky lag raha—pehle confirm karna hai."
        ],
        "REWARD_LURE": [
            "Really? What do I need to do to claim it?",
            "Okay… what’s the process for the reward?",
            "Kis cheez ka reward hai? And eligibility kya hai?"
        ],
        "BENIGN": [
            "Haan bolo—kya help chahiye?",
            "Okay, I can help. What exactly is the issue?",
            "Theek hai—problem batao, main check karta hoon."
        ],
        "UNKNOWN": [
            "Can you clarify what you need from me?",
            "What is this regarding? Please explain.",
            "Samjha nahi—thoda clearly batao kya chahiye?"
        ]
    }

    base = _pick(stage_prompts.get(stage, stage_prompts["UNKNOWN"]), rng)

    # -----------------------------
    # MODE: SOFT_ENGAGEMENT
    # -----------------------------
    if mode == "SOFT_ENGAGEMENT":
        reply = _pick([base] + soft_openers, rng)
        return {"agentReply": reply, "agentGoal": "Keep scammer engaged and gather more signals without exposure."}

    # -----------------------------
    # MODE: INTELLIGENCE_EXTRACTION
    # Stage-locking + safe routing
    # -----------------------------
    if mode == "INTELLIGENCE_EXTRACTION":

        # ✅ HARD LOCK: OTP stage must ask OTP-related questions only (progressive + 12–15+ variations)
        if stage == "OTP_FRAUD":
            return {
                "agentReply": _otp_progressive_reply(turn_index),
                "agentGoal": "Keep OTP fraud engagement realistic without sharing OTP; gather sender/SMS text/purpose and alternative verification."
            }

        # ✅ HARD LOCK: if bank/IFSC already present, do NOT downgrade to UPI-only
        if gaps["has_bank"] or gaps["has_ifsc"]:
            if gaps["need_ifsc"] and (not gaps["need_bank"]):
                return {"agentReply": _pick(ask_ifsc_only, rng), "agentGoal": "Extract missing IFSC to complete bank intelligence."}
            return {"agentReply": _pick(bank_confirm, rng), "agentGoal": "Confirm beneficiary/bank details to strengthen bank intelligence and keep scammer engaged."}

        # ✅ PHISHING path
        if stage == "PHISHING":
            if gaps["need_link"]:
                return {"agentReply": _pick(ask_link, rng), "agentGoal": "Extract phishing URL for reporting."}

            # If payment intent already present, move to receiver/bank confirmation
            if gaps["has_upi"] or has_payment_intent:
                return {"agentReply": _pick(phishing_payment_followup, rng), "agentGoal": "Continue extraction by moving phishing into payment flow (receiver/bank details)."}

            return {"agentReply": _pick(phishing_followup, rng), "agentGoal": "Keep phishing engagement realistic and gather next-step instructions."}

        # If social/urgency and link missing, ask link
        if gaps["need_link"] and stage in ["SOCIAL_ENGINEERING", "URGENCY"]:
            return {"agentReply": _pick(ask_link, rng), "agentGoal": "Extract phishing URL for reporting."}

        # ✅ UPI / payment
        if gaps["has_upi"]:
            return {"agentReply": _pick(ask_receiver_or_collect, rng), "agentGoal": "Confirm receiver name / collect / alternate UPI to extend extraction."}

        # If payment request but no UPI yet, ask UPI
        if gaps["need_upi"] and (has_payment_intent or stage == "PAYMENT_REQUEST"):
            return {"agentReply": _pick(ask_upi, rng), "agentGoal": "Extract UPI ID / receiver handle."}

        # If QR intent and UPI exists, continue collect/receiver flow
        if has_qr_intent and (not gaps["need_upi"]):
            return {"agentReply": _pick(ask_receiver_or_collect, rng), "agentGoal": "Extend conversation using QR/collect flow."}

        # If we still need bank details, ask bank
        if gaps["need_bank"]:
            return {"agentReply": _pick(ask_bank, rng), "agentGoal": "Extract bank account details."}

        # Contact details at the end
        if gaps["need_phone"] or gaps["need_email"]:
            return {"agentReply": _pick(ask_contact_details, rng), "agentGoal": "Extract contact details for intelligence."}

        followups = [
            "Okay, I noted that. What’s the next step?",
            "Done. If it fails again, what should I do?",
            "Can you confirm receiver name once more?",
            "Agar ye step ho gaya, next verification kya hoga?"
        ]
        return {"agentReply": _pick(followups, rng), "agentGoal": "Keep conversation alive for more evidence."}

    return {"agentReply": None, "agentGoal": "No action needed."}


def agent_decision(
    analysis: dict,
    conversation_history: Optional[list] = None,
    extracted_intelligence: Optional[dict] = None,
    session_id: Optional[str] = None
) -> Dict[str, Any]:

    extracted_intelligence = extracted_intelligence or {}
    conversation_history = conversation_history or []

    # turn_index = how many messages so far + 1 (stable)
    turn_index = max(1, len(conversation_history) + 1)

    if not analysis.get("scamDetected", False):
        benign_rng = _make_rng(session_id, "BENIGN_HELP", "BENIGN", turn_index)
        benign_help = [
            "Aap kaunsa app use karte ho (GPay/PhonePe/Paytm)? Main safe steps bata deta hoon.",
            "UPI PIN reset ke liye app me ‘Forgot UPI PIN’ / ‘Reset PIN’ option hota hai—kaunsa app hai?",
            "PIN reset ke liye debit card details + OTP lagta hai. Aap kaunsa bank/app use kar rahe ho?",
            "Aapka issue exactly kya hai—payment fail, PIN issue, ya account warning?",
            "App me error code aa raha hai kya? (Bas code bata do.)"
        ]
        return {
            "activated": False,
            "riskLevel": "LOW",
            "action": "ALLOW",
            "agentMode": "PASSIVE",
            "message": "No scam indicators detected",
            "agentReply": _pick(benign_help, benign_rng),
            "agentGoal": "Help user safely (benign).",
            "persona": PERSONA["style"]
        }

    score = float(analysis.get("confidenceScore", 0.0))
    scam_type = analysis.get("scamType")
    stage = analysis.get("scamStage")

    gaps = _intel_gaps(extracted_intelligence)
    evidence_lock = (
        gaps["has_any_strong"]
        or bool(extracted_intelligence.get("hasPaymentIntent"))
        or bool(extracted_intelligence.get("hasQRIntent"))
    )

    if score >= 0.8:
        reply_pack = generate_reply(
            "INTELLIGENCE_EXTRACTION", stage, scam_type, extracted_intelligence,
            session_id=session_id, turn_index=turn_index
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

    if score >= 0.5 and evidence_lock:
        reply_pack = generate_reply(
            "INTELLIGENCE_EXTRACTION", stage, scam_type, extracted_intelligence,
            session_id=session_id, turn_index=turn_index
        )
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
        reply_pack = generate_reply(
            "SOFT_ENGAGEMENT", stage, scam_type, extracted_intelligence,
            session_id=session_id, turn_index=turn_index
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