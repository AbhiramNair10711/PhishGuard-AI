import re
from url_analyzer import analyze_url

URGENCY_TERMS = [
    "urgent", "immediately", "act now", "limited time", "final warning", "today",
    "suspended", "blocked", "expire", "within 24 hours", "asap", "last chance"
]
SENSITIVE_TERMS = [
    "otp", "one-time password", "password", "pin", "cvv", "card number",
    "bank details", "account details", "login details", "verify your account",
    "social security", "aadhaar", "kyc"
]
DECEPTION_TERMS = [
    "you won", "winner", "claim your prize", "free gift", "refund", "unusual activity",
    "account will be closed", "delivery fee", "payment failed", "click here",
    "confirm your identity", "suspended"
]

def _matches(text, terms):
    low = text.lower()
    return [term for term in terms if term in low]

def analyze_message(message: str) -> dict:
    text = message.strip()
    warnings = []
    urgency = min(100, len(_matches(text, URGENCY_TERMS)) * 22)
    sensitive = min(100, len(_matches(text, SENSITIVE_TERMS)) * 28)
    deception = min(100, len(_matches(text, DECEPTION_TERMS)) * 24)

    if urgency:
        warnings.append("Urgent or threatening language was detected.")
    if sensitive:
        warnings.append("The message may request sensitive information or account verification.")
    if deception:
        warnings.append("Persuasive or commonly abused message phrases were detected.")

    urls = re.findall(r'(?:https?://|www\.)[^\s<>"\']+', text, flags=re.I)
    url_suspicion = 0
    for raw in urls:
        url_result = analyze_url(raw.rstrip(".,);]"))
        url_suspicion = max(url_suspicion, url_result["url_suspicion"])
        warnings.extend(url_result["warnings"])
    if not urls:
        url_suspicion = 0

    if text.count("!") >= 3:
        warnings.append("The message uses repeated exclamation marks to create pressure.")
        urgency = min(100, urgency + 10)
    if re.search(r"\b(click|tap)\s+(here|below)\b", text, re.I):
        warnings.append("The message encourages clicking a call-to-action link.")

    return {
        "url_suspicion": url_suspicion,
        "urgency": urgency,
        "sensitive_request": sensitive,
        "deception": deception,
        "warnings": list(dict.fromkeys(warnings)),
        "url_count": len(urls)
    }
