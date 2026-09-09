from app import app

from database.database import db
from models.case import Case
from models.evidence import Evidence
from models.event import Event

from core.evidence_processor import process_evidence

import pytest


def test_process_evidence(tmp_path):

    with app.app_context():

        # Create temporary authentication evidence
        auth_file = tmp_path / "auth.log"

        auth_file.write_text(
            "2026-09-07T09:58:00,admin,192.168.1.50,FAILURE\n"
            "2026-09-07T09:59:00,admin,192.168.1.50,FAILURE\n"
            "2026-09-07T10:00:00,admin,192.168.1.50,SUCCESS\n"
        )

        # Create test case
        case = Case(
            case_id="PROCESSOR-TEST-001",
            case_name="Evidence Processor Test",
            description="Testing the evidence processing pipeline",
        )

        db.session.add(case)
        db.session.flush()

        # Create evidence record
        evidence = Evidence(
            evidence_id="PROCESSOR-EVIDENCE-001",
            case_id=case.id,
            filename="auth.log",
            evidence_type="authentication",
            file_size=auth_file.stat().st_size,
            sha256_hash="b" * 64,
            integrity_status="Verified",
        )

        db.session.add(evidence)
        db.session.flush()

        # Process the evidence
        saved_events = process_evidence(
            case_id=case.id,
            evidence_id=evidence.id,
            file_path=auth_file,
            evidence_type="authentication",
        )

        # Verify three events were created
        assert len(saved_events) == 3

        # Verify events exist in database
        database_events = Event.query.filter_by(
            case_id=case.id
        ).all()

        assert len(database_events) == 3

        # Verify event contents
        assert database_events[0].event_type == "authentication"

        assert database_events[0].username == "admin"

        assert database_events[0].source_ip == "192.168.1.50"

        assert (
            database_events[0].description
            == "Failed login attempt for user admin from 192.168.1.50"
        )

        # Clean up
        for event in database_events:
            db.session.delete(event)

        db.session.delete(evidence)
        db.session.delete(case)

        db.session.commit()


def test_process_evidence_rejects_unknown_type(tmp_path):

    # Create a fake unsupported evidence file
    fake_file = tmp_path / "unknown.xyz"

    fake_file.write_text("test")

    # CyberTrace should reject the unsupported evidence type
    with pytest.raises(ValueError):

        process_evidence(
            case_id=1,
            evidence_id=1,
            file_path=fake_file,
            evidence_type="unknown",
        )