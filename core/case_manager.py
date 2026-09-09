import uuid

from database.database import db
from models.case import Case


def generate_case_id():
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


def create_case(case_name, description=None):
    case = Case(
        case_id=generate_case_id(),
        case_name=case_name,
        description=description,
        status="Open",
        risk_score=0,
    )

    db.session.add(case)
    db.session.commit()

    return case


def get_case_by_id(case_id):
    return Case.query.filter_by(case_id=case_id).first()


def get_all_cases():
    return Case.query.order_by(
        Case.created_at.desc()
    ).all()