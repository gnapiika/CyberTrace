import uuid

from database.database import db
from models.event import Event


def generate_event_id():
    return f"EVT-{uuid.uuid4().hex[:12].upper()}"


def save_events(case_id, evidence_id, events):
    saved_events = []

    for event_data in events:

        event = Event(
            event_id=generate_event_id(),
            case_id=case_id,
            evidence_id=evidence_id,
            event_type=event_data.get("event_type"),
            timestamp=event_data.get("timestamp"),
            username=event_data.get("username"),
            source_ip=event_data.get("source_ip"),
            destination_ip=event_data.get("destination_ip"),
            description=event_data.get("description"),
            severity=event_data.get("severity", "INFO"),
            raw_data=event_data.get("raw_data"),
        )

        db.session.add(event)
        saved_events.append(event)

    db.session.commit()

    return saved_events