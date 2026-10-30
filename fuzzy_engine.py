"""Small, transparent Mamdani-style fuzzy inference engine (no external fuzzy package needed)."""
import numpy as np

def trimf(x, abc):
    a, b, c = abc
    x = np.asarray(x, dtype=float)
    left = np.zeros_like(x)
    if b != a:
        mask = (a < x) & (x < b)
        left[mask] = (x[mask] - a) / (b - a)
    left[x == b] = 1.0
    right = np.zeros_like(x)
    if c != b:
        mask = (b < x) & (x < c)
        right[mask] = (c - x[mask]) / (c - b)
    right[x == b] = 1.0
    result = np.maximum(left, right)
    result[x == a] = 0.0 if a != b else 1.0
    result[x == c] = 0.0 if c != b else 1.0
    return np.clip(result, 0, 1)

def left_shoulder(x, a, b):
    x = np.asarray(x, dtype=float)
    return np.where(x <= a, 1.0, np.where(x >= b, 0.0, (b-x)/(b-a)))

def right_shoulder(x, a, b):
    x = np.asarray(x, dtype=float)
    return np.where(x <= a, 0.0, np.where(x >= b, 1.0, (x-a)/(b-a)))

def memberships(value):
    v = float(max(0, min(100, value)))
    return {
        "low": float(left_shoulder(np.array([v]), 20, 45)[0]),
        "medium": float(trimf(np.array([v]), [25, 50, 75])[0]),
        "high": float(right_shoulder(np.array([v]), 55, 80)[0]),
    }

def assess_risk(features):
    names = ["url_suspicion", "urgency", "sensitive_request", "deception"]
    vals = {n: float(max(0, min(100, features.get(n, 0)))) for n in names}
    m = {n: memberships(v) for n, v in vals.items()}

    # Mamdani-style rules: antecedents use min; output sets are clipped and max-aggregated.
    x = np.linspace(0, 100, 1001)
    low = left_shoulder(x, 15, 40)
    medium = trimf(x, [25, 50, 75])
    high = trimf(x, [55, 75, 92])
    critical = right_shoulder(x, 80, 95)
    aggregate = np.zeros_like(x)
    fired = []

    rules = [
        ("Low risk when all signals are low", min(m["url_suspicion"]["low"], m["urgency"]["low"],
          m["sensitive_request"]["low"], m["deception"]["low"]), low),
        ("Medium risk when at least one signal is moderate", max(
          min(m["url_suspicion"]["medium"], m["urgency"]["low"]),
          min(m["urgency"]["medium"], m["sensitive_request"]["low"]),
          min(m["deception"]["medium"], m["url_suspicion"]["low"])), medium),
        ("High risk when URL suspicion combines with urgency or deception", max(
          min(m["url_suspicion"]["high"], m["urgency"]["medium"]),
          min(m["url_suspicion"]["medium"], m["deception"]["high"]),
          min(m["sensitive_request"]["high"], m["urgency"]["medium"]),
          min(m["urgency"]["high"], m["deception"]["medium"])), high),
        ("Critical risk when multiple strong signals are present", max(
          min(m["url_suspicion"]["high"], m["sensitive_request"]["high"]),
          min(m["urgency"]["high"], m["sensitive_request"]["high"]),
          min(m["deception"]["high"], m["sensitive_request"]["high"])), critical),
    ]
    for label, strength, output_mf in rules:
        aggregate = np.maximum(aggregate, np.minimum(strength, output_mf))
        if strength > 0.01:
            fired.append({"rule": label, "strength": round(float(strength), 3)})

    area = float(np.sum(aggregate))
    if area <= 1e-9:
        score = float(max(vals.values()))
    else:
        score = float(np.sum(x * aggregate) / area)
    score = round(max(0, min(100, score)), 1)
    category = "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"
    summaries = {
        "Low": "Few configured warning signals were found. Still verify unexpected requests independently.",
        "Medium": "Some suspicious signals were found. Avoid sharing sensitive information until verified.",
        "High": "Several warning signals are present. Do not click or reply until you verify the sender through an official channel.",
        "Critical": "Strong warning signals are present. Do not open the link or provide credentials, payment details, or OTPs."
    }
    return {"score": score, "category": category, "summary": summaries[category], "rules_fired": fired}
