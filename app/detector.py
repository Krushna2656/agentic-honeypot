import re
from typing import List, Dict, Any, Optional

# -----------------------------
# Keyword & Pattern Definitions
# -----------------------------

SCAM_KEYWORDS = {
    "RECON": ["hello", "hi", "are you there"],
    "SOCIAL_ENGINEERING": [
        "kyc", "verify", "update", "account", "suspended",
        "blocked", "limited", "security", "aapka account", "blocked hai",
        "verification", "customer care", "support team"
    ],
    "URGENCY": ["urgent", "immediately", "turant", "asap", "today", "within 1 hour", "right now"],
    "PAYMENT_REQUEST": [
        "send money", "pay", "transfer", "refund", "processing fee", "charge",
        "upi", "scan", "qr", "collect request", "request money"
    ],
    "OTP_FRAUD": ["otp", "one time password", "share otp", "send otp"],
    "REWARD_LURE": ["win", "lottery", "prize", "cashback", "reward", "congratulations", "gift"]
}

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"

# -----------------------------
# Helper Functions
# -----------------------------

def _contains_any(text: str, words: List[str]) -> bool:
    return any(w in text for w in words)


def detect_stage(
    text: str,
    has_upi_id: bool = False,
    has_url: bool = False,
    has_bank: bool = False,
    has_otp: bool = False
) -> str:
    """
    Smarter stage detection:
    - PHISHING if URL is present
    - PAYMENT_REQUEST only if UPI ID is present OR actual payment intent exists
    - OTP_FRAUD if OTP keywords present
    - URGENCY if urgency words exist
    - SOCIAL_ENGINEERING for verification/account manipulation
    - REWARD_LURE for lottery/prize
    - RECON for greetings
    """
    text = text.lower()

    # Strong signal stages first
    if has_url:
        return "PHISHING"

    if has_otp or _contains_any(text, SCAM_KEYWORDS["OTP_FRAUD"]):
        return "OTP_FRAUD"

    payment_intent = (
        has_upi_id
        or _contains_any(text, ["send money", "pay", "transfer", "processing fee", "charge", "qr", "scan", "collect request", "request money"])
    )
    if payment_intent:
        return "PAYMENT_REQUEST"

    if _contains_any(text, SCAM_KEYWORDS["URGENCY"]):
        return "URGENCY"

    if _contains_any(text, SCAM_KEYWORDS["SOCIAL_ENGINEERING"]):
        return "SOCIAL_ENGINEERING"

    if _contains_any(text, SCAM_KEYWORDS["REWARD_LURE"]):
        return "REWARD_LURE"

    if _contains_any(text, SCAM_KEYWORDS["RECON"]):
        return "RECON"

    return "UNKNOWN"


def history_boost(history: Optional[List[Any]]) -> float:
    """
    Boost based on scam signals appearing repeatedly in conversation history.
    """
    if not history:
        return 0.0

    repeat_hits = 0
    for msg in history:
        msg_text = getattr(msg, "text", "").lower()
        if any(
            kw in msg_text
            for keywords in SCAM_KEYWORDS.values()
            for kw in keywords
        ):
            repeat_hits += 1

    # stronger, but capped
    return min(0.08 * repeat_hits, 0.32)


# -----------------------------
# Main Detection Function
# -----------------------------

def detect_scam(message_text: str, history: list = None) -> Dict[str, Any]:
    text = message_text.lower()

    # Pattern extraction
    upi_ids = re.findall(UPI_REGEX, message_text)
    urls = re.findall(URL_REGEX, message_text)
    bank_accounts = re.findall(BANK_REGEX, message_text)
    ifsc_codes = re.findall(IFSC_REGEX, message_text)

    # Keyword hits (unique)
    keyword_hits = []
    for keywords in SCAM_KEYWORDS.values():
        keyword_hits.extend([kw for kw in keywords if kw in text])
    keyword_hits = list(set(keyword_hits))

    has_otp = ("otp" in text) or ("one time password" in text)

    scam_stage = detect_stage(
        text,
        has_upi_id=bool(upi_ids),
        has_url=bool(urls),
        has_bank=bool(bank_accounts) or bool(ifsc_codes),
        has_otp=has_otp
    )

    # -----------------------------
    # Confidence Scoring (more realistic)
    # -----------------------------
    score = 0.0

    # keyword base
    score += len(keyword_hits) * 0.10

    # strong indicators
    if urls:
        score += 0.45
    if upi_ids:
        score += 0.40
    if bank_accounts or ifsc_codes:
        score += 0.45
    if has_otp:
        score += 0.55  # OTP is very high risk

    # stage-based boosts (helps multi-turn)
    if scam_stage == "SOCIAL_ENGINEERING":
        score += 0.20
    elif scam_stage == "URGENCY":
        score += 0.20
    elif scam_stage == "REWARD_LURE":
        score += 0.25
    elif scam_stage == "PAYMENT_REQUEST":
        score += 0.30
    elif scam_stage == "PHISHING":
        score += 0.30
    elif scam_stage == "OTP_FRAUD":
        score += 0.35

    # history boost
    score += history_boost(history)

    score = min(score, 1.0)
    scam_detected = score >= 0.5

    # -----------------------------
    # Scam type classification (judge-friendly)
    # -----------------------------
    scam_type = None
    if urls:
        scam_type = "PHISHING"
    elif has_otp:
        scam_type = "OTP_FRAUD"
    elif upi_ids:
        scam_type = "UPI_FRAUD"
    elif bank_accounts or ifsc_codes:
        scam_type = "BANK_FRAUD"
    elif scam_stage in ["SOCIAL_ENGINEERING", "REWARD_LURE", "URGENCY"]:
        scam_type = scam_stage

    # Fallback: if detected but still None
    if scam_detected and scam_type is None:
        scam_type = "GENERIC_SCAM"

    return {
        "scamDetected": scam_detected,
        "confidenceScore": round(score, 2),
        "scamStage": scam_stage,
        "scamType": scam_type,
        "indicators": {
            "keywords": keyword_hits,
            "upiIds": upi_ids,
            "bankAccounts": bank_accounts,
            "ifscCodes": ifsc_codes,
            "links": urls
        }
    }
