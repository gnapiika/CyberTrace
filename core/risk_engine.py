# ==========================================
# CYBERTRACE RISK ENGINE
# ==========================================

SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 25,
    "CRITICAL": 40,
}


# Additional weighting for important detection rules.
# These values are intentionally small because
# severity remains the primary risk factor.

RULE_BONUS = {
    "BRUTE_FORCE_SUCCESS": 5,
    "SUSPICIOUS_DOWNLOAD_EXECUTION": 5,
    "SUSPICIOUS_PROCESS_CHAIN": 5,
    "USB_FILE_TRANSFER": 5,
    "SUSPICIOUS_NETWORK_ACTIVITY": 3,
    "CREATE_EXECUTE_DELETE": 3,
    "MULTI_STAGE_ACTIVITY": 10,
}


# ==========================================
# NORMALIZE SEVERITY
# ==========================================

def normalize_severity(severity):
    """
    Normalize an alert severity value.

    Unknown or missing values are treated as INFO.
    """

    if not severity:
        return "INFO"

    severity = str(severity).upper().strip()

    if severity not in SEVERITY_POINTS:
        return "INFO"

    return severity


# ==========================================
# CALCULATE RISK SCORE
# ==========================================

def calculate_risk_score(alerts):
    """
    Calculate the overall investigation risk score.

    Each alert contributes points based on severity.
    Detection rules may also contribute a small bonus.

    The final score is limited to a maximum of 100.
    """

    score = 0

    for alert in alerts:
        severity = normalize_severity(
            alert.get("severity", "INFO")
        )

        score += SEVERITY_POINTS[severity]

        rule_id = alert.get("rule_id")

        if rule_id:
            score += RULE_BONUS.get(
                str(rule_id).upper(),
                0
            )

    return min(score, 100)


# ==========================================
# RISK BREAKDOWN
# ==========================================

def get_risk_breakdown(alerts):
    """
    Return a breakdown of the alerts contributing
    to the investigation risk score.

    This is useful for the dashboard and PDF report.
    """

    breakdown = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    severity_points = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    rule_bonuses = 0

    for alert in alerts:
        severity = normalize_severity(
            alert.get("severity", "INFO")
        )

        breakdown[severity] += 1

        severity_points[severity] += SEVERITY_POINTS[
            severity
        ]

        rule_id = alert.get("rule_id")

        if rule_id:
            rule_bonuses += RULE_BONUS.get(
                str(rule_id).upper(),
                0
            )

    total_severity_points = sum(
        severity_points.values()
    )

    total_score = min(
        total_severity_points + rule_bonuses,
        100
    )

    return {
        "alert_counts": breakdown,
        "severity_points": severity_points,
        "severity_score": total_severity_points,
        "rule_bonus": rule_bonuses,
        "total_score": total_score,
    }


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


# ==========================================
# RISK SUMMARY
# ==========================================

def get_risk_summary(alerts):
    """
    Return a complete risk assessment containing
    score, level, alert count, and breakdown.
    """

    score = calculate_risk_score(alerts)
    level = get_risk_level(score)
    breakdown = get_risk_breakdown(alerts)

    return {
        "score": score,
        "level": level,
        "alert_count": len(alerts),
        "breakdown": breakdown,
    }