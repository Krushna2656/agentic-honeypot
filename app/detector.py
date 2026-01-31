import re
from typing import List, Dict, Any, Optional

# -----------------------------
# Keyword & Pattern Definitions
# -----------------------------
SCAM_KEYWORDS = {
    "RECON": ["hello", "hi", "are you there", "hii", "hey"],
    "SOCIAL_ENGINEERING": [
        "kyc", "verify", "verification", "update", "account", "suspended",
        "blocked", "limit", "limited", "security", "aapka account", "blocked hai",
        "customer care", "support team", "bank team", "document", "re-kyc",
        "link open", "login", "credentials", "netbanking", "debit card"
    ],
    "URGENCY": [
        "urgent", "immediately", "turant", "asap", "today", "within 1 hour",
        "right now", "last chance", "final warning", "action required", "24 hours"
    ],
    "PAYMENT_REQUEST": [
        "send money", "pay", "transfer", "refund", "processing fee", "charge",
        "upi", "scan", "qr", "collect request", "request money", "pay now",
        "activation fee", "wallet", "deposit"
    ],
    "OTP_FRAUD": ["otp", "one time password", "share otp", "send otp", "otp code"],
    "REWARD_LURE": [
        "win", "lottery", "prize", "cashback", "reward",
        "congratulations", "gift", "free money"
    ]
}

# Patterns
UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"

# URL risk boosters
SUSPICIOUS_URL_HINTS = ["kyc", "login", "verify", "secure", "update", "suspend", "bank", "upi", "payment"]
SHORTENER_HINTS = ["bit.ly", "tinyurl", "t.co", "cutt.ly", "rb.gy", "is.gd"]

# Benign context (reduce false positives)
BENIGN_CONTEXT = ["balance", "statement", "branch", "atm", "debit", "credit", "passbook", "upi pin"]


def _contains_any(text: str, words: List[str]) -> bool:
    return any(w in text for w in words)


def _url_risk_score(urls: List[str]) -> float:
    """
    Boost score when URLs look like phishing:
    - shorteners
    - kyc/login/verify/secure keywords
    """
    if not urls:
        return 0.0

    score = 0.0
    for u in urls:
        low = u.lower()
        if any(s in low for s in SHORTENER_HINTS):
            score += 0.20
        if any(h in low for h in SUSPICIOUS_URL_HINTS):
            score += 0.15

    return min(score, 0.45)


def _benign_guard(text: str, keyword_hits: List[str], has_strong_signal: bool) -> float:
    """
    Reduce false positives:
    If only weak signals exist and message looks like normal banking talk, reduce score.
    """
    if has_strong_signal:
        return 0.0

    if _contains_any(text, BENIGN_CONTEXT) and len(keyword_hits) <= 2:
        return -0.20

    # Greetings-only
    if _contains_any(text, SCAM_KEYWORDS["RECON"]) and len(keyword_hits) <= 1:
        return -0.25

    return 0.0


def detect_stage(
    text: str,
    has_upi_id: bool = False,
    has_url: bool = False,
    has_bank: bool = False,
    has_otp: bool = False
) -> str:
    """
    Priority stage detection:
    PHISHING > OTP_FRAUD > PAYMENT_REQUEST > URGENCY > SOCIAL_ENGINEERING > REWARD_LURE > RECON
    """
    text = (text or "").lower()

    if has_url:
        return "PHISHING"

    if has_otp or _contains_any(text, SCAM_KEYWORDS["OTP_FRAUD"]):
        return "OTP_FRAUD"

    payment_intent = has_upi_id or _contains_any(text, SCAM_KEYWORDS["PAYMENT_REQUEST"])
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
    Boost score based on repeated scam signals across history.
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

    return min(0.08 * repeat_hits, 0.32)


def detect_scam(message_text: str, history: list = None) -> Dict[str, Any]:
    text = (message_text or "").lower()

    # Pattern extraction
    upi_ids = re.findall(UPI_REGEX, message_text or "")
    urls = re.findall(URL_REGEX, message_text or "")
    bank_accounts = re.findall(BANK_REGEX, message_text or "")
    ifsc_codes = re.findall(IFSC_REGEX, message_text or "")

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
    # Confidence Scoring (calibrated)
    # -----------------------------
    score = 0.0

    # keyword base (small)
    score += len(keyword_hits) * 0.08

    # strong indicators
    if urls:
        score += 0.40
        score += _url_risk_score(urls)

    if upi_ids:
        score += 0.38

    if bank_accounts or ifsc_codes:
        score += 0.40

    if has_otp:
        score += 0.60  # OTP = high risk

    # stage boosts
    stage_boost = {
        "SOCIAL_ENGINEERING": 0.15,
        "URGENCY": 0.15,
        "REWARD_LURE": 0.18,
        "PAYMENT_REQUEST": 0.20,
        "PHISHING": 0.20,
        "OTP_FRAUD": 0.22
    }
    score += stage_boost.get(scam_stage, 0.0)

    # multi-turn memory
    score += history_boost(history)

    # benign guard
    has_strong_signal = bool(urls or upi_ids or bank_accounts or ifsc_codes or has_otp)
    score += _benign_guard(text, keyword_hits, has_strong_signal)

    score = max(0.0, min(score, 1.0))
    scam_detected = score >= 0.5

    # -----------------------------
    # Scam type: ONLY if detected (important fix)
    # -----------------------------
    scam_type = None
    if scam_detected:
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
        else:
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
