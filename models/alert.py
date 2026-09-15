from datetime import datetime

from database.database import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    alert_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )

    rule_id = db.Column(
        db.String(100),
        nullable=False
    )

    alert_name = db.Column(
        db.String(200),
        nullable=False
    )

    severity = db.Column(
        db.String(30),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False
    )

    event_ids = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    case = db.relationship(
        "Case",
        backref=db.backref(
            "alerts",
            lazy=True
        )
    )

    def __repr__(self):
        return f"<Alert {self.alert_id}>"