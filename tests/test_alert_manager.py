from datetime import datetime

from app import app

from database.database import db

from models.case import Case
from models.alert import Alert

from core.alert_manager import (
    save_alert,
    save_alerts,
    get_case_alerts,
    delete_case_alerts,
)


# ==========================================
# SAVE ONE ALERT
# ==========================================

def test_save_alert():

    with app.app_context():

        case = Case(
            case_id="ALERT-TEST-001",
            case_name="Alert Manager Test",
            description="Testing alert storage",
        )

        db.session.add(
            case
        )

        db.session.flush()

        alert_data = {

            "rule_id":
                "BRUTE_FORCE_SUCCESS",

            "name":
                "Possible Brute-Force Attack",

            "severity":
                "HIGH",

            "description":
                "Multiple failed authentication "
                "attempts were followed by a "
                "successful login.",

            "timestamp":
                datetime(
                    2026,
                    9,
                    7,
                    10,
                    3,
                    0,
                ),

            "event_ids": [
                "EVT-001",
                "EVT-002",
                "EVT-003",
            ],
        }

        alert = save_alert(
            case_id=case.id,
            alert_data=alert_data,
        )

        assert alert.id is not None

        assert (
            alert.rule_id
            == "BRUTE_FORCE_SUCCESS"
        )

        assert (
            alert.alert_name
            == "Possible Brute-Force Attack"
        )

        assert (
            alert.severity
            == "HIGH"
        )

        assert (
            alert.case_id
            == case.id
        )

        assert (
            alert.created_at
            is not None
        )

        # Clean up
        db.session.delete(
            alert
        )

        db.session.delete(
            case
        )

        db.session.commit()


# ==========================================
# SAVE MULTIPLE ALERTS
# ==========================================

def test_save_multiple_alerts():

    with app.app_context():

        case = Case(
            case_id="ALERT-TEST-002",
            case_name="Multiple Alert Test",
            description="Testing multiple alerts",
        )

        db.session.add(
            case
        )

        db.session.flush()

        alerts = [

            {
                "rule_id":
                    "BRUTE_FORCE_SUCCESS",

                "name":
                    "Possible Brute-Force Attack",

                "severity":
                    "HIGH",

                "description":
                    "Multiple failed logins.",

                "timestamp":
                    datetime(
                        2026,
                        9,
                        7,
                        10,
                        3,
                    ),

                "event_ids":
                    ["EVT-001"],
            },

            {
                "rule_id":
                    "USB_FILE_TRANSFER",

                "name":
                    "Possible USB Data Transfer",

                "severity":
                    "HIGH",

                "description":
                    "USB file transfer detected.",

                "timestamp":
                    datetime(
                        2026,
                        9,
                        7,
                        10,
                        20,
                    ),

                "event_ids":
                    [
                        "EVT-002",
                        "EVT-003",
                    ],
            },

        ]

        saved_alerts = save_alerts(
            case_id=case.id,
            alerts=alerts,
        )

        assert len(
            saved_alerts
        ) == 2

        database_alerts = Alert.query.filter_by(
            case_id=case.id
        ).all()

        assert len(
            database_alerts
        ) == 2

        # Clean up
        for alert in database_alerts:

            db.session.delete(
                alert
            )

        db.session.delete(
            case
        )

        db.session.commit()


# ==========================================
# GET CASE ALERTS
# ==========================================

def test_get_case_alerts():

    with app.app_context():

        case = Case(
            case_id="ALERT-TEST-003",
            case_name="Get Alerts Test",
        )

        db.session.add(
            case
        )

        db.session.flush()

        alert_data = {

            "rule_id":
                "SUSPICIOUS_PROCESS_CHAIN",

            "name":
                "Suspicious Process Chain",

            "severity":
                "HIGH",

            "description":
                "Potentially suspicious process.",

            "timestamp":
                datetime(
                    2026,
                    9,
                    7,
                    10,
                    7,
                ),

            "event_ids":
                ["EVT-100"],
        }

        save_alert(
            case.id,
            alert_data,
        )

        alerts = get_case_alerts(
            case.id
        )

        assert len(
            alerts
        ) == 1

        assert (
            alerts[0].rule_id
            == "SUSPICIOUS_PROCESS_CHAIN"
        )

        delete_case_alerts(
            case.id
        )

        assert (
            get_case_alerts(
                case.id
            )
            == []
        )

        db.session.delete(
            case
        )

        db.session.commit()