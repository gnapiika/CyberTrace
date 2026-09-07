from core.risk_engine import calculate_risk_score, get_risk_level


def test_calculate_risk_score():
    alerts = [
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
    ]

    score = calculate_risk_score(alerts)

    assert score == 45


def test_risk_score_cannot_exceed_100():
    alerts = [
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL"},
        {"severity": "CRITICAL"},
    ]

    score = calculate_risk_score(alerts)

    assert score == 100


def test_get_risk_level():
    assert get_risk_level(10) == "LOW"
    assert get_risk_level(30) == "MODERATE"
    assert get_risk_level(50) == "MEDIUM"
    assert get_risk_level(70) == "HIGH"
    assert get_risk_level(90) == "CRITICAL"