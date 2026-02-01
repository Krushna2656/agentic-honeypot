import re
from typing import Dict, Any

# -----------------------------
# Regex Patterns
# -----------------------------
UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
PHONE_REGEX = r"\b[6-9]\d{9}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

# Extra: UPI deep links + QR hints
UPI_URI_REGEX = r"upi://pay[^\s]+"

QR_HINTS = ["scan", "qr", "barcode", "upi qr", "scan code", "qr code"]
PAYMENT_WORDS = [
    "pay", "transfer", "send money", "deposit", "processing fee", "charge",
    "collect request", "request money", "upi", "₹", "rs", "inr"
]


def _dedupe(items):
    return list(dict.fromkeys(items or []))


def extract_features(message_text: str) -> Dict[str, Any]:
    """
    Extract raw intelligence signals from a message.
    (Confidence + sourceTurn are added in main.py where we know turn number.)
    """
    raw = message_text or ""
    text = raw.lower()

    upi_ids = re.findall(UPI_REGEX, raw)
    urls = re.findall(URL_REGEX, raw)
    upi_uris = re.findall(UPI_URI_REGEX, raw)

    bank_accounts = re.findall(BANK_REGEX, raw)
    ifsc_codes = re.findall(IFSC_REGEX, raw)
    phones = re.findall(PHONE_REGEX, raw)
    emails = re.findall(EMAIL_REGEX, raw)

    # Heuristic signals
    has_qr_intent = any(word in text for word in QR_HINTS) or (len(upi_uris) > 0)
    has_payment_intent = any(word in text for word in PAYMENT_WORDS)

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
