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
PAYMENT_WORDS = ["pay", "transfer", "send money", "deposit", "processing fee", "charge", "collect request", "request money", "upi", "₹", "rs", "inr"]


def extract_features(message_text: str) -> Dict[str, Any]:
    text = (message_text or "").lower()

    upi_ids = re.findall(UPI_REGEX, message_text or "")
    urls = re.findall(URL_REGEX, message_text or "")
    upi_uris = re.findall(UPI_URI_REGEX, message_text or "")

    bank_accounts = re.findall(BANK_REGEX, message_text or "")
    ifsc_codes = re.findall(IFSC_REGEX, message_text or "")
    phones = re.findall(PHONE_REGEX, message_text or "")
    emails = re.findall(EMAIL_REGEX, message_text or "")

    # Heuristic signals
    has_qr_intent = any(word in text for word in QR_HINTS) or (len(upi_uris) > 0)
    has_payment_intent = any(word in text for word in PAYMENT_WORDS)

    # URLs also include UPI deep links if any
    phishing_links = list(dict.fromkeys(urls + upi_uris))

    return {
        # Raw stats
        "length": len(message_text or ""),
        "hasNumbers": any(char.isdigit() for char in (message_text or "")),
        "hasUpperCase": any(char.isupper() for char in (message_text or "")),
        "specialChars": sum(not c.isalnum() for c in (message_text or "")),

        # High-value intelligence
        "upiIds": list(dict.fromkeys(upi_ids)),
        "bankAccounts": list(dict.fromkeys(bank_accounts)),
        "ifscCodes": list(dict.fromkeys(ifsc_codes)),
        "phishingLinks": phishing_links,
        "phoneNumbers": list(dict.fromkeys(phones)),
        "emailIds": list(dict.fromkeys(emails)),

        # Behavioral signals (for agent strategy)
        "hasQRIntent": has_qr_intent,
        "hasPaymentIntent": has_payment_intent
    }
