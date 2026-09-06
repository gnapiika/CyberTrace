SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 25,
    "CRITICAL": 40,
}


def calculate_risk_score(alerts):
    score = 0

    for alert in alerts:
        severity = alert.get("severity", "INFO")
        score += SEVERITY_POINTS.get(severity, 0)

    return min(score, 100)


def get_risk_level(score):
    if score <= 20:
        return "LOW"

    if score <= 40:
        return "MODERATE"

    if score <= 60:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"