import json
import uuid

from database.database import db
from models.alert import Alert


# ==========================================
# GENERATE ALERT ID
# ==========================================

def generate_alert_id():
    """
    Generate a unique CyberTrace alert ID.
    """

    return (
        f"ALR-{uuid.uuid4().hex[:12].upper()}"
    )


# ==========================================
# SAVE ONE ALERT
# ==========================================

def save_alert(
    case_id,
    alert_data,
):
    """
    Convert a detection-engine alert dictionary
    into a database Alert record.
    """

    alert = Alert(

        alert_id=generate_alert_id(),

        case_id=case_id,

        rule_id=alert_data.get(
            "rule_id"
        ),

        alert_name=alert_data.get(
            "name"
        ),

        severity=alert_data.get(
            "severity",
            "INFO"
        ),

        description=alert_data.get(
            "description",
            ""
        ),

        timestamp=alert_data.get(
            "timestamp"
        ),

        event_ids=json.dumps(
            alert_data.get(
                "event_ids",
                []
            )
        ),
    )

    db.session.add(
        alert
    )

    db.session.commit()

    return alert


# ==========================================
# SAVE MULTIPLE ALERTS
# ==========================================

def save_alerts(
    case_id,
    alerts,
):
    """
    Save all detection-engine alerts
    belonging to a case.

    Returns the database Alert objects.
    """

    saved_alerts = []

    for alert_data in alerts:

        alert = Alert(

            alert_id=generate_alert_id(),

            case_id=case_id,

            rule_id=alert_data.get(
                "rule_id"
            ),

            alert_name=alert_data.get(
                "name"
            ),

            severity=alert_data.get(
                "severity",
                "INFO"
            ),

            description=alert_data.get(
                "description",
                ""
            ),

            timestamp=alert_data.get(
                "timestamp"
            ),

            event_ids=json.dumps(
                alert_data.get(
                    "event_ids",
                    []
                )
            ),
        )

        db.session.add(
            alert
        )

        saved_alerts.append(
            alert
        )

    db.session.commit()

    return saved_alerts


# ==========================================
# GET CASE ALERTS
# ==========================================

def get_case_alerts(
    case_id
):
    """
    Return all alerts for a case,
    newest first.
    """

    return Alert.query.filter_by(
        case_id=case_id
    ).order_by(
        Alert.timestamp.desc()
    ).all()


# ==========================================
# DELETE CASE ALERTS
# ==========================================

def delete_case_alerts(
    case_id
):
    """
    Remove all generated alerts for a case.

    This allows alerts to be regenerated
    from the complete event history.
    """

    alerts = Alert.query.filter_by(
        case_id=case_id
    ).all()

    for alert in alerts:

        db.session.delete(
            alert
        )

    db.session.commit()