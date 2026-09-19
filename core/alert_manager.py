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

    return f"ALR-{uuid.uuid4().hex[:12].upper()}"


# ==========================================
# ALERT KEY
# ==========================================

def get_alert_key(alert_data):
    """
    Generate a stable key used to identify
    duplicate alerts.

    Alerts with the same rule and the same
    triggering events are treated as duplicates.
    """

    rule_id = alert_data.get("rule_id", "")

    event_ids = alert_data.get(
        "event_ids",
        []
    )

    normalized_event_ids = tuple(
        sorted(
            str(event_id)
            for event_id in event_ids
        )
    )

    return (
        str(rule_id),
        normalized_event_ids,
    )


# ==========================================
# SAVE ONE ALERT
# ==========================================

def save_alert(
    case_id,
    alert_data,
):
    """
    Save one detection-engine alert.

    If an identical alert already exists for
    the case, return the existing alert instead
    of creating a duplicate.
    """

    alert_key = get_alert_key(
        alert_data
    )

    existing_alerts = Alert.query.filter_by(
        case_id=case_id,
        rule_id=alert_data.get("rule_id"),
    ).all()

    for existing_alert in existing_alerts:

        try:
            existing_event_ids = tuple(
                sorted(
                    str(event_id)
                    for event_id in json.loads(
                        existing_alert.event_ids or "[]"
                    )
                )
            )
        except (TypeError, json.JSONDecodeError):
            existing_event_ids = ()

        existing_key = (
            str(existing_alert.rule_id),
            existing_event_ids,
        )

        if existing_key == alert_key:
            return existing_alert

    alert = Alert(
        alert_id=generate_alert_id(),
        case_id=case_id,
        rule_id=alert_data.get("rule_id"),
        alert_name=alert_data.get("name"),
        severity=alert_data.get(
            "severity",
            "INFO",
        ),
        description=alert_data.get(
            "description",
            "",
        ),
        timestamp=alert_data.get(
            "timestamp",
        ),
        event_ids=json.dumps(
            alert_data.get(
                "event_ids",
                [],
            )
        ),
    )

    db.session.add(alert)
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
    Save multiple detection-engine alerts.

    Duplicate alerts are skipped automatically.

    Returns the database Alert objects that
    exist after processing the supplied alerts.
    """

    saved_alerts = []

    for alert_data in alerts:

        alert = save_alert(
            case_id=case_id,
            alert_data=alert_data,
        )

        saved_alerts.append(
            alert
        )

    return saved_alerts


# ==========================================
# GET CASE ALERTS
# ==========================================

def get_case_alerts(
    case_id,
):
    """
    Return all alerts for a case,
    newest first.
    """

    return (
        Alert.query
        .filter_by(
            case_id=case_id
        )
        .order_by(
            Alert.timestamp.desc()
        )
        .all()
    )


# ==========================================
# GET ALERTS BY SEVERITY
# ==========================================

def get_alerts_by_severity(
    case_id,
    severity,
):
    """
    Return alerts for a case matching
    the requested severity.
    """

    return (
        Alert.query
        .filter_by(
            case_id=case_id,
            severity=str(
                severity
            ).upper(),
        )
        .order_by(
            Alert.timestamp.desc()
        )
        .all()
    )


# ==========================================
# COUNT CASE ALERTS
# ==========================================

def count_case_alerts(
    case_id,
):
    """
    Return the total number of alerts
    generated for a case.
    """

    return Alert.query.filter_by(
        case_id=case_id
    ).count()


# ==========================================
# COUNT ALERTS BY SEVERITY
# ==========================================

def count_alerts_by_severity(
    case_id,
):
    """
    Return alert counts grouped by severity.
    """

    counts = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    alerts = Alert.query.filter_by(
        case_id=case_id
    ).all()

    for alert in alerts:

        severity = str(
            alert.severity or "INFO"
        ).upper()

        if severity in counts:
            counts[severity] += 1

    return counts


# ==========================================
# DELETE CASE ALERTS
# ==========================================

def delete_case_alerts(
    case_id,
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