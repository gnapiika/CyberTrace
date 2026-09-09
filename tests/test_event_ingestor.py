from datetime import datetime

from app import app
from database.database import db
from models.case import Case
from models.evidence import Evidence
from models.event import Event

from core.event_ingestor import save_events


def test_save_events():

    with app.app_context():

        case = Case(
            case_id="TEST-CASE-001",
            case_name="Test Investigation",
            description="Automated test case",
        )

        db.session.add(case)
        db.session.flush()

        evidence = Evidence(
            evidence_id="TEST-EVIDENCE-001",
            case_id=case.id,
            filename="test.log",
            evidence_type="authentication",
            file_size=100,
            sha256_hash="a" * 64,
            integrity_status="Verified",
        )

        db.session.add(evidence)
        db.session.flush()

        events = [
            {
                "event_type": "authentication",
                "timestamp": datetime(2026, 9, 7, 10, 0, 0),
                "description": "Successful login",
                "username": "admin",
                "source_ip": "192.168.1.50",
                "severity": "INFO",
                "raw_data": "test authentication event",
            }
        ]

        saved_events = save_events(
            case_id=case.id,
            evidence_id=evidence.id,
            events=events,
        )

        assert len(saved_events) == 1

        saved_event = Event.query.filter_by(
            case_id=case.id
        ).first()

        assert saved_event is not None

        assert saved_event.event_type == "authentication"

        assert saved_event.username == "admin"

        assert saved_event.source_ip == "192.168.1.50"

        assert saved_event.description == "Successful login"

        assert saved_event.severity == "INFO"

        assert saved_event.evidence_id == evidence.id

        # Clean up test data
        db.session.delete(saved_event)
        db.session.delete(evidence)
        db.session.delete(case)
        db.session.commit()