import re
from typing import Dict, List

# -----------------------------
# Regex Patterns
# -----------------------------

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
BANK_REGEX = r"\b\d{9,18}\b"
IFSC_REGEX = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
PHONE_REGEX = r"\b[6-9]\d{9}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

QR_HINTS = ["scan", "qr", "barcode", "upi qr", "scan code"]
PAYMENT_WORDS = ["pay", "transfer", "send money", "deposit", "processing fee"]

# -----------------------------
# Intelligence Extractor
# -----------------------------

def extract_features(message_text: str) -> Dict[str, any]:
    text = message_text.lower()

    upi_ids = re.findall(UPI_REGEX, message_text)
    urls = re.findall(URL_REGEX, message_text)
    bank_accounts = re.findall(BANK_REGEX, message_text)
    ifsc_codes = re.findall(IFSC_REGEX, message_text)
    phones = re.findall(PHONE_REGEX, message_text)
    emails = re.findall(EMAIL_REGEX, message_text)

    # Heuristic signals
    has_qr_intent = any(word in text for word in QR_HINTS)
    has_payment_intent = any(word in text for word in PAYMENT_WORDS)

    return {
        # Raw stats
        "length": len(message_text),
        "hasNumbers": any(char.isdigit() for char in message_text),
        "hasUpperCase": any(char.isupper() for char in message_text),
        "specialChars": sum(not c.isalnum() for c in message_text),

        # High-value intelligence
        "upiIds": upi_ids,
        "bankAccounts": bank_accounts,
        "ifscCodes": ifsc_codes,
        "phishingLinks": urls,
        "phoneNumbers": phones,
        "emailIds": emails,

        # Behavioral signals (for agent strategy)
        "hasQRIntent": has_qr_intent,
        "hasPaymentIntent": has_payment_intent
    }
