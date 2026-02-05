import re
from typing import List, Dict, Any, Optional

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
        "right now", "last chance", "final warning", "action required", "24 hours", "2 hours", "minutes"
    ],
    "PAYMENT_REQUEST": [
        "send money", "pay", "transfer", "refund", "processing fee", "charge",
        "upi", "scan", "qr", "collect request", "request money", "pay now",
        "activation fee", "wallet", "deposit", "beneficiary", "neft", "imps"
    ],
    "OTP_FRAUD": ["otp", "one time password", "share otp", "send otp", "otp code"],
    "REWARD_LURE": [
        "win", "lottery", "prize", "cashback", "reward",
        "congratulations", "gift", "free money"
    ]
}

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"

SUSPICIOUS_URL_HINTS = ["kyc", "login", "verify", "secure", "update", "suspend", "bank", "upi", "payment"]
SHORTENER_HINTS = ["bit.ly", "tinyurl", "t.co", "cutt.ly", "rb.gy", "is.gd"]

BENIGN_CONTEXT = [
    "balance", "statement", "branch", "atm", "debit", "credit", "passbook",
    "upi pin", "pin reset", "reset pin", "forgot pin", "forgot upi pin",
    "how to", "kaise", "kya", "help", "forgot", "reset"
]

VALID_UPI_SUFFIXES = {
    "upi",
    "okhdfcbank", "okicici", "oksbi", "okaxis", "okpnb", "okbob", "okboi",
    "ybl", "ibl", "axl", "paytm", "apl", "ptys", "jio",
    "icici", "hdfcbank", "sbi", "axisbank", "pnb", "bob", "boi", "kotak",
    "indus", "idfcbank", "yesbank", "unionbank", "canarabank",
    "fbl", "hsbc", "citi", "rbl",
    "airtel", "freecharge"
}


def _contains_any(text: str, words: List[str]) -> bool:
    return any(w in text for w in words)


def _get_text(msg: Any) -> str:
    if isinstance(msg, dict):
        return (msg.get("text") or "")
    return (getattr(msg, "text", "") or "")


def _is_valid_upi_handle(candidate: str) -> bool:
    if not candidate or "@" not in candidate:
        return False
    local, suffix = candidate.strip().split("@", 1)
    local = local.strip()
    suffix = suffix.strip().lower()
    if len(local) < 2:
        return False
    return suffix in VALID_UPI_SUFFIXES


def _filter_valid_upi(candidates: List[str]) -> List[str]:
    out = []
    for c in candidates or []:
        if _is_valid_upi_handle(c):
            out.append(c)
    return list(dict.fromkeys(out))


def _url_risk_score(urls: List[str]) -> float:
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
    if has_strong_signal:
        return 0.0
    if _contains_any(text, BENIGN_CONTEXT) and len(keyword_hits) <= 3:
        return -0.30
    if _contains_any(text, SCAM_KEYWORDS["RECON"]) and len(keyword_hits) <= 1:
        return -0.25
    return 0.0


def history_boost(history: Optional[List[Any]]) -> float:
    if not history:
        return 0.0
    repeat_hits = 0
    for msg in history:
        msg_text = _get_text(msg).lower()
        if any(kw in msg_text for keywords in SCAM_KEYWORDS.values() for kw in keywords):
            repeat_hits += 1
    return min(0.08 * repeat_hits, 0.32)


def _scan_history_strong_signals(history: Optional[List[Any]]) -> Dict[str, bool]:
    any_url = False
    any_upi = False
    any_bank = False
    any_ifsc = False
    any_otp = False

    for msg in history or []:
        t = _get_text(msg)
        low = (t or "").lower()

        if re.findall(URL_REGEX, t or ""):
            any_url = True

        upi_candidates = re.findall(UPI_REGEX, t or "")
        if _filter_valid_upi(upi_candidates):
            any_upi = True

        if re.findall(BANK_REGEX, t or ""):
            any_bank = True
        if re.findall(IFSC_REGEX, t or ""):
            any_ifsc = True
        if ("otp" in low) or ("one time password" in low) or _contains_any(low, SCAM_KEYWORDS["OTP_FRAUD"]):
            any_otp = True

    return {"any_url": any_url, "any_upi": any_upi, "any_bank": any_bank, "any_ifsc": any_ifsc, "any_otp": any_otp}


def _detect_stage_current(text_lower: str, has_url_current: bool, has_otp_current: bool, has_payment_current: bool) -> str:
    # ✅ stage is decided from CURRENT message only (no latch)
    if has_url_current:
        return "PHISHING"
    if has_otp_current:
        return "OTP_FRAUD"
    if has_payment_current:
        return "PAYMENT_REQUEST"
    if _contains_any(text_lower, SCAM_KEYWORDS["SOCIAL_ENGINEERING"]):
        return "SOCIAL_ENGINEERING"
    if _contains_any(text_lower, SCAM_KEYWORDS["URGENCY"]):
        return "URGENCY"
    if _contains_any(text_lower, SCAM_KEYWORDS["REWARD_LURE"]):
        return "REWARD_LURE"
    if _contains_any(text_lower, SCAM_KEYWORDS["RECON"]):
        return "RECON"
    return "UNKNOWN"


def detect_scam(message_text: str, history: list = None) -> Dict[str, Any]:
    raw = (message_text or "")
    text = raw.lower()

    upi_candidates = re.findall(UPI_REGEX, raw)
    upi_ids = _filter_valid_upi(upi_candidates)

    urls = re.findall(URL_REGEX, raw)
    bank_accounts = re.findall(BANK_REGEX, raw)
    ifsc_codes = re.findall(IFSC_REGEX, raw)

    has_otp_current = ("otp" in text) or ("one time password" in text) or _contains_any(text, SCAM_KEYWORDS["OTP_FRAUD"])
    has_url_current = bool(urls)
    has_payment_current = bool(upi_candidates or bank_accounts or ifsc_codes) or _contains_any(text, SCAM_KEYWORDS["PAYMENT_REQUEST"])

    hist = history or []
    hist_flags = _scan_history_strong_signals(hist)

    # for scamType (overall)
    has_url_any = has_url_current or hist_flags["any_url"]
    has_upi_any = bool(upi_ids) or hist_flags["any_upi"]
    has_bank_any = bool(bank_accounts) or bool(ifsc_codes) or hist_flags["any_bank"] or hist_flags["any_ifsc"]
    has_otp_any = bool(has_otp_current) or hist_flags["any_otp"]

    keyword_hits = []
    for keywords in SCAM_KEYWORDS.values():
        keyword_hits.extend([kw for kw in keywords if kw in text])
    keyword_hits = list(set(keyword_hits))

    scam_stage = _detect_stage_current(text, has_url_current, has_otp_current, has_payment_current)

    score = 0.0
    score += len(keyword_hits) * 0.08

    if urls:
        score += 0.40
        score += _url_risk_score(urls)

    if upi_ids:
        score += 0.38

    if bank_accounts or ifsc_codes:
        score += 0.40

    if has_otp_current:
        score += 0.60

    # cumulative evidence booster
    if (not urls) and has_url_any:
        score += 0.10
    if (not upi_ids) and has_upi_any:
        score += 0.10
    if (not (bank_accounts or ifsc_codes)) and has_bank_any:
        score += 0.10
    if (not has_otp_current) and has_otp_any:
        score += 0.12

    stage_boost = {
        "SOCIAL_ENGINEERING": 0.15,
        "URGENCY": 0.15,
        "REWARD_LURE": 0.18,
        "PAYMENT_REQUEST": 0.20,
        "PHISHING": 0.20,
        "OTP_FRAUD": 0.22
    }
    score += stage_boost.get(scam_stage, 0.0)
    score += history_boost(hist)

    has_strong_signal = bool(urls or upi_ids or bank_accounts or ifsc_codes or has_otp_current)
    score += _benign_guard(text, keyword_hits, has_strong_signal)

    if not has_strong_signal and scam_stage == "PAYMENT_REQUEST":
        payment_keywords = SCAM_KEYWORDS.get("PAYMENT_REQUEST", [])
        if any(pk in text for pk in payment_keywords):
            score = min(score, 0.49)

    score = max(0.0, min(score, 1.0))
    scam_detected = score >= 0.5

    if not scam_detected:
        return {
            "scamDetected": False,
            "confidenceScore": round(score, 2),
            "scamStage": "BENIGN",
            "scamType": None,
            "indicators": {
                "keywords": keyword_hits,
                "upiIds": upi_ids,
                "bankAccounts": bank_accounts,
                "ifscCodes": ifsc_codes,
                "links": urls
            }
        }

    if has_url_any:
        scam_type = "PHISHING"
    elif has_otp_any:
        scam_type = "OTP_FRAUD"
    elif has_upi_any:
        scam_type = "UPI_FRAUD"
    elif has_bank_any:
        scam_type = "BANK_FRAUD"
    elif scam_stage in ["SOCIAL_ENGINEERING", "REWARD_LURE", "URGENCY"]:
        scam_type = scam_stage
    else:
        scam_type = "GENERIC_SCAM"

    return {
        "scamDetected": True,
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