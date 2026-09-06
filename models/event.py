from datetime import datetime

from database.database import db


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    event_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence.id"),
        nullable=True
    )

    event_type = db.Column(
        db.String(50),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False
    )

    username = db.Column(
        db.String(100),
        nullable=True
    )

    source_ip = db.Column(
        db.String(100),
        nullable=True
    )

    destination_ip = db.Column(
        db.String(100),
        nullable=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    severity = db.Column(
        db.String(30),
        default="INFO"
    )

    raw_data = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    case = db.relationship(
        "Case",
        backref=db.backref("events", lazy=True)
    )

    evidence = db.relationship(
        "Evidence",
        backref=db.backref("events", lazy=True)
    )

    def __repr__(self):
        return f"<Event {self.event_id}>"