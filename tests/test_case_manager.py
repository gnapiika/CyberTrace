from app import app

from database.database import db
from models.case import Case

from core.case_manager import (
    create_case,
    get_case_by_id,
    get_all_cases,
)


def test_create_case():

    with app.app_context():

        case = create_case(
            case_name="Case Manager Test",
            description="Testing case creation",
        )

        assert case.id is not None
        assert case.case_id.startswith("CASE-")
        assert case.case_name == "Case Manager Test"
        assert case.status == "Open"
        assert case.risk_score == 0

        database_case = Case.query.filter_by(
            case_id=case.case_id
        ).first()

        assert database_case is not None

        db.session.delete(database_case)
        db.session.commit()


def test_get_case_by_id():

    with app.app_context():

        case = create_case(
            case_name="Lookup Test",
            description="Testing case lookup",
        )

        found_case = get_case_by_id(case.case_id)

        assert found_case is not None
        assert found_case.case_id == case.case_id
        assert found_case.case_name == "Lookup Test"

        db.session.delete(found_case)
        db.session.commit()


def test_get_all_cases():

    with app.app_context():

        case = create_case(
            case_name="List Test",
            description="Testing case listing",
        )

        cases = get_all_cases()

        assert len(cases) >= 1
        assert any(
            item.case_id == case.case_id
            for item in cases
        )

        db.session.delete(case)
        db.session.commit()