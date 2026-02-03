import re
from typing import Dict, Any, List

# -----------------------------
# Regex Patterns
# -----------------------------
# Broad match for candidate UPI-like strings (we will validate suffix)
UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"

URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
PHONE_REGEX = r"\b[6-9]\d{9}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

# Extra: UPI deep links + QR hints
UPI_URI_REGEX = r"upi://pay[^\s]+"

QR_HINTS = ["scan", "qr", "barcode", "upi qr", "scan code", "qr code"]

# ✅ FIX: "upi" word alone should NOT mean payment intent (UPI PIN change etc.)
# NOTE: We will NOT use substring matching on these words anymore.
PAYMENT_WORDS = [
    "pay", "transfer", "send money", "deposit", "processing fee", "charge",
    "collect request", "request money", "₹", "rs", "inr"
]

# -----------------------------
# ✅ Payment intent regex (word-boundary)
# -----------------------------
# Avoid substring issues like: "payment" contains "pay"
PAYMENT_VERBS_REGEX = re.compile(r"\b(pay|transfer|deposit|charge|refund|send)\b", re.IGNORECASE)
CURRENCY_WORD_REGEX = re.compile(r"\b(rs|inr)\b", re.IGNORECASE)

# -----------------------------
# ✅ UPI Validation (PSP handles)
# -----------------------------
# Most common UPI PSP suffixes in India.
# We keep this list reasonably broad for hackathon accuracy.
VALID_UPI_SUFFIXES = {
    "upi",
    "okhdfcbank", "okicici", "oksbi", "okaxis", "okpnb", "okbob", "okboi",
    "ybl", "ibl", "axl", "paytm", "apl", "ptys", "jio",
    "icici", "hdfcbank", "sbi", "axisbank", "pnb", "bob", "boi", "kotak",
    "indus", "idfcbank", "yesbank", "unionbank", "canarabank",
    "fbl", "hsbc", "citi", "rbl",
    # add a few commonly seen wallet/merchant style handles
    "airtel", "freecharge"
}


def _dedupe(items: List[str]):
    return list(dict.fromkeys(items or []))


def _is_valid_upi_handle(candidate: str) -> bool:
    """
    Validates candidate like: name@psp
    - must have '@'
    - suffix must be in VALID_UPI_SUFFIXES
    - avoids false positives like "support@helpdesk" (not a PSP suffix)
    """
    if not candidate or "@" not in candidate:
        return False

    cand = candidate.strip()
    parts = cand.split("@", 1)
    if len(parts) != 2:
        return False

    local, suffix = parts[0].strip(), parts[1].strip().lower()

    if len(local) < 2:
        return False

    return suffix in VALID_UPI_SUFFIXES


def extract_features(message_text: str) -> Dict[str, Any]:
    """
    Extract raw intelligence signals from a message.
    (Confidence + sourceTurn are added in main.py where we know turn number.)
    """
    raw = message_text or ""
    text = raw.lower()

    # Raw extraction
    upi_candidates = re.findall(UPI_REGEX, raw)
    urls = re.findall(URL_REGEX, raw)
    upi_uris = re.findall(UPI_URI_REGEX, raw)

    bank_accounts = re.findall(BANK_REGEX, raw)
    ifsc_codes = re.findall(IFSC_REGEX, raw)
    phones = re.findall(PHONE_REGEX, raw)
    emails = re.findall(EMAIL_REGEX, raw)

    # ✅ FIX: remove phone numbers from bank_accounts
    if bank_accounts:
        bank_accounts = [b for b in bank_accounts if not re.fullmatch(PHONE_REGEX, b)]

    # ✅ FIX: Tighten UPI extraction using PSP suffix validation
    # This prevents email-like strings such as "support@helpdesk" from being treated as UPI.
    upi_ids: List[str] = []
    for c in _dedupe(upi_candidates):
        if _is_valid_upi_handle(c):
            upi_ids.append(c)

    # Heuristic signals
    has_qr_intent = any(word in text for word in QR_HINTS) or (len(upi_uris) > 0)

    # ✅ FIX: Payment intent should be true only for real payment signals
    # 1) upi://pay deep link => payment intent
    # 2) payment verbs as standalone words (NOT substring)
    # 3) currency markers: ₹ OR standalone rs/inr
    has_currency_symbol = "₹" in raw
    has_currency_word = bool(CURRENCY_WORD_REGEX.search(text))
    has_payment_verb = bool(PAYMENT_VERBS_REGEX.search(text))

    has_payment_intent = (len(upi_uris) > 0) or has_payment_verb or has_currency_symbol or has_currency_word

    # URLs also include UPI deep links if any
    phishing_links = _dedupe(urls + upi_uris)

    return {
        # Raw stats
        "length": len(raw),
        "hasNumbers": any(char.isdigit() for char in raw),
        "hasUpperCase": any(char.isupper() for char in raw),
        "specialChars": sum(not c.isalnum() for c in raw),

        # High-value intelligence (RAW lists)
        "upiIds": _dedupe(upi_ids),
        "bankAccounts": _dedupe(bank_accounts),
        "ifscCodes": _dedupe(ifsc_codes),
        "phishingLinks": phishing_links,
        "phoneNumbers": _dedupe(phones),
        "emailIds": _dedupe(emails),

        # Behavioral signals (for agent strategy)
        "hasQRIntent": has_qr_intent,
        "hasPaymentIntent": has_payment_intent
    }
