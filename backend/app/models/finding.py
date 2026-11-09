from datetime import datetime, timezone
from ..extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=False, index=True)
    category = db.Column(db.String(128), nullable=False)
    severity = db.Column(db.String(32), nullable=False)  # Critical, High, Medium, Low
    detection_method = db.Column(db.String(32), nullable=False)  # Rule, ML, Rule + ML
    confidence = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    file_path = db.Column(db.String(512), nullable=False)
    line_number = db.Column(db.Integer, nullable=True)
    masked_preview = db.Column(db.String(256), nullable=False)  # Never raw secret!
    reason = db.Column(db.String(512), nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    rule_id = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "category": self.category,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "confidence": round(self.confidence, 4),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "masked_preview": self.masked_preview,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "rule_id": self.rule_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

