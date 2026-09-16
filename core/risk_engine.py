# ==========================================
# RISK SEVERITY POINTS
# ==========================================

SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 25,
    "CRITICAL": 40,
}


# ==========================================
# CALCULATE RISK SCORE
# ==========================================

def calculate_risk_score(alerts):
    """
    Calculate the overall investigation risk score.

    Each alert contributes points based on its
    severity.

    The final score is limited to a maximum of 100.
    """

    score = 0

    for alert in alerts:

        severity = alert.get(
            "severity",
            "INFO"
        )

        severity = severity.upper()

        score += SEVERITY_POINTS.get(
            severity,
            0
        )

    return min(
        score,
        100
    )


# ==========================================
# DETERMINE RISK LEVEL
# ==========================================

def get_risk_level(score):
    """
    Convert a numerical risk score into
    a human-readable risk level.

    0-20    -> LOW
    21-40   -> MODERATE
    41-60   -> MEDIUM
    61-80   -> HIGH
    81-100  -> CRITICAL
    """

    if score <= 20:

        return "LOW"

    if score <= 40:

        return "MODERATE"

    if score <= 60:

        return "MEDIUM"

    if score <= 80:

        return "HIGH"

    return "CRITICAL"