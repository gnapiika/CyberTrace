from datetime import datetime

from core.timeline import build_timeline


class MockEvent:
    def __init__(self, timestamp, event_type):
        self.timestamp = timestamp
        self.event_type = event_type


def test_build_timeline_sorts_events():

    events = [
        MockEvent(
            datetime(2026, 9, 7, 12, 0, 0),
            "network",
        ),
        MockEvent(
            datetime(2026, 9, 7, 10, 0, 0),
            "authentication",
        ),
        MockEvent(
            datetime(2026, 9, 7, 11, 0, 0),
            "file",
        ),
    ]

    timeline = build_timeline(events)

    assert timeline[0].event_type == "authentication"
    assert timeline[1].event_type == "file"
    assert timeline[2].event_type == "network"