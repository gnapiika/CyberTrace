from datetime import datetime

from database.database import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

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

    rule_name = db.Column(
        db.String(200),
        nullable=False
    )

    severity = db.Column(
        db.String(30),
        nullable=False
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    status = db.Column(
        db.String(30),
        default="Open"
    )

    case = db.relationship(
        "Case",
        backref=db.backref("alerts", lazy=True)
    )

    def __repr__(self):
        return f"<Alert {self.alert_id}>"