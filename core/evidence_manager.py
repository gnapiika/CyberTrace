import os
import uuid

from database.database import db
from models.evidence import Evidence

from utils.hash_utils import calculate_sha256
from utils.evidence_utils import extract_evidence


def generate_evidence_id():
    return f"EVD-{uuid.uuid4().hex[:8].upper()}"


def register_evidence(
    case_id,
    file_path,
    evidence_type,
):
    file_path = os.path.abspath(file_path)

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"Evidence file not found: {file_path}"
        )

    file_size = os.path.getsize(file_path)

    sha256_hash = calculate_sha256(file_path)

    evidence = Evidence(
        evidence_id=generate_evidence_id(),
        case_id=case_id,
        filename=os.path.basename(file_path),
        evidence_type=evidence_type,
        file_size=file_size,
        sha256_hash=sha256_hash,
        integrity_status="Verified",
    )

    db.session.add(evidence)
    db.session.commit()

    return evidence


def get_evidence_by_id(evidence_id):
    return Evidence.query.filter_by(
        evidence_id=evidence_id
    ).first()


def get_case_evidence(case_id):
    return Evidence.query.filter_by(
        case_id=case_id
    ).order_by(
        Evidence.uploaded_at.desc()
    ).all()


def extract_registered_evidence(
    file_path,
    destination,
):
    return extract_evidence(
        zip_path=file_path,
        destination=destination,
    )