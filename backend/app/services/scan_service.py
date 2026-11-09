import os
import time
import shutil
import logging
from werkzeug.utils import secure_filename
from ..extensions import db
from ..models.scan import Scan
from ..models.finding import Finding
from .storage_service import StorageService
from .archive_service import ArchiveService, ArchiveValidationError
from .risk_service import calculate_security_score
from ..scanner.result_combiner import process_line_findings

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self):
        self.storage = StorageService()
        self.archive = ArchiveService()

    def execute_scan(self, file_storage, user_id: int) -> Scan:
        start_time = time.perf_counter()

        # Sanitize display filename
        raw_name = file_storage.filename or "uploaded_project.zip"
        safe_display_name = secure_filename(os.path.basename(raw_name)) or "project.zip"

        # Check extension
        if not safe_display_name.lower().endswith(".zip"):
            raise ArchiveValidationError("Only .zip archives are supported.")

        # Create initial scan database record
        scan = Scan(
            user_id=user_id,
            original_filename=safe_display_name,
            status="processing",
            ml_model_version="rf-v1.0.0"
        )
        db.session.add(scan)
        db.session.commit()

        storage_key = None
        local_archive_path = None
        extract_dir = None

        try:
            # 1. Store archive privately (S3 in cloud mode, local temp dir in dev mode)
            storage_key, local_archive_path = self.storage.save_archive(file_storage, user_id)
            if self.storage.backend == "s3":
                scan.s3_object_key = storage_key

            # 2. Safely inspect and extract archive
            extract_dir = self.archive.extract_safely(local_archive_path)

            # 3. Filter eligible text files
            scannable_files, files_scanned, files_skipped, _ = self.archive.get_scannable_files(extract_dir)

            all_findings = []

            # 4. Process each scannable file line by line
            for rel_path, full_path in scannable_files:
                for line_number, line_content in self.archive.read_file_lines(full_path):
                    # Process detection pipeline on line
                    line_findings = process_line_findings(
                        rel_path=rel_path,
                        line_number=line_number,
                        line_content=line_content
                    )
                    all_findings.extend(line_findings)

            # 5. Calculate severity counts and security score
            score, counts = calculate_security_score(all_findings)

            # 6. Persist findings (strictly masked preview only!)
            for f in all_findings:
                finding_record = Finding(
                    scan_id=scan.id,
                    category=f.category,
                    severity=f.severity,
                    detection_method=f.detection_method,
                    confidence=f.confidence,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    masked_preview=f.masked_preview,
                    reason=f.reason,
                    recommendation=f.recommendation,
                    rule_id=f.rule_id
                )
                db.session.add(finding_record)

            # 7. Update scan record
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            scan.status = "completed"
            scan.security_score = score
            scan.total_findings = counts["Total"]
            scan.critical_count = counts["Critical"]
            scan.high_count = counts["High"]
            scan.medium_count = counts["Medium"]
            scan.low_count = counts["Low"]
            scan.files_scanned = files_scanned
            scan.files_skipped = files_skipped
            scan.scan_duration_ms = duration_ms

            db.session.commit()

            # Optional notification dispatch if critical findings detected
            if counts["Critical"] > 0:
                try:
                    from .sns_service import SNSService
                    SNSService().notify_critical_findings(
                        scan_id=scan.id,
                        project_name=scan.original_filename,
                        critical_count=counts["Critical"],
                        score=score
                    )
                except Exception as sns_err:
                    logger.warning("Could not send SNS notification: %s", str(sns_err))

            return scan

        except Exception as e:
            db.session.rollback()
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            scan.status = "failed"
            scan.error_message = str(e)
            scan.scan_duration_ms = duration_ms
            db.session.commit()
            logger.error("Scan %s failed: %s", scan.id, str(e), exc_info=True)
            raise

        finally:
            # Always clean up extracted temporary directory and local temporary files
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir, ignore_errors=True)
            if local_archive_path:
                self.storage.cleanup_archive(s3_key=storage_key, local_path=local_archive_path)

