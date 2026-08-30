SEVERITY_SCORES = {
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 95,
}

EVENT_TYPE_BONUSES = {
    "malware": 5,
    "brute_force": 10,
    "data_exfiltration": 15,
    "unauthorized_access": 10,
}


def calculate_risk_score(severity, event_type):
    severity = severity.lower().strip()
    event_type = event_type.lower().strip()

    if severity not in SEVERITY_SCORES:
        raise ValueError("Invalid severity")

    score = SEVERITY_SCORES[severity]
    score += EVENT_TYPE_BONUSES.get(event_type, 0)

    return min(score, 100)
