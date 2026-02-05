# 🕵️ Agentic Honeypot – Scam Detection & Intelligence Extraction API

An **AI-powered Agentic Honey-Pot** designed to detect scam intent, autonomously engage scammers in believable multi-turn conversations, extract actionable intelligence, and report final results to the GUVI evaluation system.

This project is built for the **GUVI Hackathon – Agentic Honey-Pot for Scam Detection & Intelligence Extraction**.

---

## 🚀 Key Highlights

* 🔍 **Real-time scam detection** (UPI fraud, phishing, bank fraud, OTP scams, refund scams)
* 🤖 **Autonomous agent** with human-like persona (non-technical, polite, anxious)
* 🔁 **Multi-turn conversation handling** using session memory
* 🧠 **Stage-aware responses** (Recon → Social Engineering → Payment → OTP → Bank)
* 🧾 **Structured intelligence extraction** with confidence & sourceTurn
* 🔐 **API-key protected public REST API**
* 📡 **Mandatory GUVI callback implemented & verified (HTTP 200)**

---

## 🧠 System Architecture (High Level)

1. Incoming message received via `/honeypot` API
2. Scam detection engine analyzes message + history
3. If scam detected → Agent is activated
4. Agent replies autonomously & adapts across turns
5. Intelligence extracted cumulatively
6. Final intelligence sent to GUVI callback endpoint

---

## 🔐 Authentication

All requests **must** include:

```
x-api-key: YOUR_SECRET_API_KEY
```

Invalid or missing key returns **401 Unauthorized**.

---

## 📥 API Endpoint

### POST `/honeypot`

#### Request Body (First Message)

```json
{
  "sessionId": "abc123-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

#### Request Body (Follow-up Message)

```json
{
  "sessionId": "abc123-session-id",
  "message": {
    "sender": "scammer",
    "text": "Pay ₹10 to verify. UPI: test@okicici",
    "timestamp": 1770005528731
  },
  "conversationHistory": [
    {"sender": "scammer", "text": "Your bank account will be blocked today."},
    {"sender": "user", "text": "Why is my account being blocked?"}
  ]
}
```

---

## 📤 API Response Format (MANDATORY)

```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

> ⚠️ No extra fields are returned to maintain GUVI tester compatibility.

---

## 🤖 Agent Behavior

The autonomous agent:

* Never reveals scam detection
* Never accuses or threatens
* Asks for **one detail at a time**
* Adapts based on scam stage
* Sounds human, anxious, cooperative

Example replies:

* "Which UPI ID should I use exactly?"
* "If payment fails, can you share bank details?"
* "OTP share karna safe nahi lag raha…"

---

## 🧾 Extracted Intelligence

The system can extract:

* UPI IDs
* Bank account numbers
* IFSC codes
* Phishing URLs
* Phone numbers
* Email IDs

Each signal includes:

* `value`
* `confidence`
* `sourceTurn`

---

## 📡 Mandatory GUVI Callback (Implemented ✅)

### Callback Endpoint

```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

### Payload Sent

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 6,
  "extractedIntelligence": {
    "bankAccounts": ["556677889900"],
    "upiIds": ["test@okicici"],
    "phishingLinks": ["https://fake-kyc-link.in"],
    "phoneNumbers": [],
    "suspiciousKeywords": ["urgent", "verify", "upi"]
  },
  "agentNotes": "Scammer used urgency and payment redirection tactics"
}
```

### Callback Status

* ✅ Verified live
* ✅ HTTP 200 success received

---

## 🧪 Testing Status

* ✔️ Multi-turn conversations tested
* ✔️ Phishing flow tested
* ✔️ UPI → Bank escalation tested
* ✔️ Refund scam false-positive avoidance tested
* ✔️ Callback delivery confirmed

---

## 🛡 Ethics & Safety

* ❌ No impersonation of real individuals
* ❌ No illegal instructions
* ❌ No victim data harvesting
* ✅ Responsible intelligence collection

---

## 🏁 One-Line Summary

> **An AI-powered agentic honeypot API that detects scam messages, autonomously engages scammers in multi-turn conversations, extracts actionable intelligence, and reports final results to GUVI for evaluation.**

---

## 👨‍💻 Author

**Krushna Jadhav**
Agentic Honeypot – GUVI Hackathon Submission

---

✅ Submission-ready | 🚀 International hackathon grade | 🏆
