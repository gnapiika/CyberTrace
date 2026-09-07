from datetime import datetime

from core.event_normalizer import normalize_event


def test_normalize_event():
    event = normalize_event(
        event_type="authentication",
        timestamp="2026-09-07T10:30:00",
        description="Successful login",
        username="admin",
        source_ip="192.168.1.10",
        severity="INFO",
    )

    assert event["event_type"] == "authentication"
    assert event["description"] == "Successful login"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.10"
    assert event["severity"] == "INFO"
    assert isinstance(event["timestamp"], datetime)