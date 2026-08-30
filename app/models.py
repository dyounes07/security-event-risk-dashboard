from datetime import datetime
from . import db


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    risk_score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat(),
        }
