from datetime import datetime

from database.database import db


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)

    evidence_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("cases.id"),
        nullable=False
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    evidence_type = db.Column(
        db.String(50),
        nullable=False
    )

    file_size = db.Column(
        db.Integer,
        nullable=False
    )

    sha256_hash = db.Column(
        db.String(64),
        nullable=False
    )

    integrity_status = db.Column(
        db.String(30),
        default="Pending"
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    case = db.relationship(
        "Case",
        backref=db.backref("evidence", lazy=True)
    )

    def __repr__(self):
        return f"<Evidence {self.evidence_id}>"