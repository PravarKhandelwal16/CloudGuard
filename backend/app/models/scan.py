import uuid
from datetime import datetime, timezone
from ..extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    s3_object_key = db.Column(db.String(512), nullable=True)
    status = db.Column(db.String(32), default="completed", nullable=False)  # completed, failed, processing
    security_score = db.Column(db.Integer, default=100, nullable=False)
    total_findings = db.Column(db.Integer, default=0, nullable=False)
    critical_count = db.Column(db.Integer, default=0, nullable=False)
    high_count = db.Column(db.Integer, default=0, nullable=False)
    medium_count = db.Column(db.Integer, default=0, nullable=False)
    low_count = db.Column(db.Integer, default=0, nullable=False)
    files_scanned = db.Column(db.Integer, default=0, nullable=False)
    files_skipped = db.Column(db.Integer, default=0, nullable=False)
    scan_duration_ms = db.Column(db.Integer, default=0, nullable=False)
    ml_model_version = db.Column(db.String(64), default="rf-v1.0.0", nullable=False)
    error_message = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan", order_by="Finding.id")

    def to_dict(self, include_findings=False):
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "original_filename": self.original_filename,
            "status": self.status,
            "security_score": self.security_score,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "scan_duration_ms": self.scan_duration_ms,
            "ml_model_version": self.ml_model_version,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data

