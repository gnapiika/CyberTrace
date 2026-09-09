from app import app

from database.database import db
from models.case import Case
from models.evidence import Evidence

from core.evidence_manager import (
    register_evidence,
    get_evidence_by_id,
    get_case_evidence,
)


def test_register_evidence(tmp_path):

    with app.app_context():

        evidence_file = tmp_path / "test_evidence.txt"

        evidence_file.write_text(
            "CyberTrace evidence test"
        )

        case = Case(
            case_id="EVIDENCE-MANAGER-CASE",
            case_name="Evidence Manager Test",
            description="Testing evidence registration",
        )

        db.session.add(case)
        db.session.flush()

        evidence = register_evidence(
            case_id=case.id,
            file_path=evidence_file,
            evidence_type="text",
        )

        assert evidence.id is not None
        assert evidence.evidence_id.startswith("EVD-")
        assert evidence.filename == "test_evidence.txt"
        assert evidence.evidence_type == "text"
        assert evidence.file_size > 0
        assert len(evidence.sha256_hash) == 64
        assert evidence.integrity_status == "Verified"

        database_evidence = Evidence.query.filter_by(
            evidence_id=evidence.evidence_id
        ).first()

        assert database_evidence is not None

        db.session.delete(database_evidence)
        db.session.delete(case)
        db.session.commit()


def test_get_evidence_by_id(tmp_path):

    with app.app_context():

        evidence_file = tmp_path / "lookup.txt"

        evidence_file.write_text(
            "Evidence lookup test"
        )

        case = Case(
            case_id="EVIDENCE-LOOKUP-CASE",
            case_name="Evidence Lookup Test",
        )

        db.session.add(case)
        db.session.flush()

        evidence = register_evidence(
            case_id=case.id,
            file_path=evidence_file,
            evidence_type="text",
        )

        found_evidence = get_evidence_by_id(
            evidence.evidence_id
        )

        assert found_evidence is not None
        assert (
            found_evidence.evidence_id
            == evidence.evidence_id
        )

        db.session.delete(found_evidence)
        db.session.delete(case)
        db.session.commit()


def test_get_case_evidence(tmp_path):

    with app.app_context():

        evidence_file = tmp_path / "list.txt"

        evidence_file.write_text(
            "Evidence listing test"
        )

        case = Case(
            case_id="EVIDENCE-LIST-CASE",
            case_name="Evidence List Test",
        )

        db.session.add(case)
        db.session.flush()

        evidence = register_evidence(
            case_id=case.id,
            file_path=evidence_file,
            evidence_type="text",
        )

        evidence_list = get_case_evidence(case.id)

        assert len(evidence_list) >= 1

        assert any(
            item.evidence_id == evidence.evidence_id
            for item in evidence_list
        )

        for item in evidence_list:
            if item.case_id == case.id:
                db.session.delete(item)

        db.session.delete(case)
        db.session.commit()