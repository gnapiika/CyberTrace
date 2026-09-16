from datetime import datetime, timedelta

from core.correlation_engine import (
    events_within_window,
    correlate_events,
    build_correlation_summary,
)


class MockEvent:
    def __init__(
        self,
        event_id,
        event_type,
        timestamp,
        description,
        username=None,
        source_ip=None,
        destination_ip=None,
    ):
        self.event_id = event_id
        self.event_type = event_type
        self.timestamp = timestamp
        self.description = description
        self.username = username
        self.source_ip = source_ip
        self.destination_ip = destination_ip


def test_events_within_window():

    first = MockEvent(
        "EVT-1",
        "authentication",
        datetime(2026, 9, 7, 10, 0),
        "Failed login",
    )

    second = MockEvent(
        "EVT-2",
        "process",
        datetime(2026, 9, 7, 10, 5),
        "Process executed",
    )

    assert events_within_window(first, second)


def test_events_outside_window():

    first = MockEvent(
        "EVT-1",
        "authentication",
        datetime(2026, 9, 7, 10, 0),
        "Failed login",
    )

    second = MockEvent(
        "EVT-2",
        "process",
        datetime(2026, 9, 7, 10, 30),
        "Process executed",
    )

    assert not events_within_window(first, second)


def test_correlate_events_by_username():

    timestamp = datetime(2026, 9, 7, 10, 0)

    auth_event = MockEvent(
        "EVT-1",
        "authentication",
        timestamp,
        "Successful login",
        username="admin",
    )

    process_event = MockEvent(
        "EVT-2",
        "process",
        timestamp + timedelta(minutes=3),
        "PowerShell executed",
        username="admin",
    )

    correlations = correlate_events(
        [auth_event, process_event]
    )

    assert len(correlations) == 1
    assert correlations[0]["event_count"] if "event_count" in correlations[0] else len(
        correlations[0]["events"]
    ) == 2


def test_correlate_browser_file_process():

    timestamp = datetime(2026, 9, 7, 10, 0)

    browser_event = MockEvent(
        "EVT-1",
        "browser",
        timestamp,
        "Downloaded suspicious file",
    )

    file_event = MockEvent(
        "EVT-2",
        "file",
        timestamp + timedelta(minutes=2),
        "File created",
    )

    process_event = MockEvent(
        "EVT-3",
        "process",
        timestamp + timedelta(minutes=4),
        "PowerShell executed",
    )

    correlations = correlate_events(
        [browser_event, file_event, process_event]
    )

    assert len(correlations) >= 1

    evidence_types = set(correlations[0]["evidence_types"])

    assert "browser" in evidence_types
    assert "file" in evidence_types
    assert "process" in evidence_types


def test_build_correlation_summary():

    timestamp = datetime(2026, 9, 7, 10, 0)

    event_one = MockEvent(
        "EVT-1",
        "browser",
        timestamp,
        "Downloaded file",
    )

    event_two = MockEvent(
        "EVT-2",
        "process",
        timestamp + timedelta(minutes=2),
        "PowerShell executed",
    )

    correlations = correlate_events(
        [event_one, event_two]
    )

    summary = build_correlation_summary(
        correlations[0]
    )

    assert summary["event_count"] == 2
    assert "browser" in summary["evidence_types"]
    assert "process" in summary["evidence_types"]