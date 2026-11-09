import os
import uuid
import shutil
import logging
from pathlib import Path
from flask import current_app

logger = logging.getLogger(__name__)


class StorageService:
    """Manages archive storage across local filesystem and AWS S3."""

    def __init__(self, backend=None):
        self.backend = backend or current_app.config.get("STORAGE_BACKEND", "local").lower()
        self.region = current_app.config.get("AWS_REGION", "ap-south-1")
        self.bucket = current_app.config.get("S3_BUCKET_NAME", "cloudguard-uploads")
        self.local_dir = current_app.config.get("LOCAL_UPLOAD_DIR", "temp_scans")

    def save_archive(self, file_storage, user_id: int) -> tuple[str, str]:
        """
        Saves uploaded file to configured backend.
        Returns (storage_path_or_key, local_inspectable_path).
        """
        unique_id = str(uuid.uuid4())
        safe_filename = f"{unique_id}.zip"

        if self.backend == "s3":
            import boto3
            from botocore.exceptions import ClientError

            s3_key = f"uploads/{user_id}/{safe_filename}"
            local_temp_path = os.path.join(self.local_dir, safe_filename)
            os.makedirs(os.path.dirname(local_temp_path), exist_ok=True)

            # Save locally first to read and upload
            file_storage.seek(0)
            file_storage.save(local_temp_path)

            try:
                s3_client = boto3.client("s3", region_name=self.region)
                s3_client.upload_file(
                    local_temp_path,
                    self.bucket,
                    s3_key,
                    ExtraArgs={"ServerSideEncryption": "AES256"}
                )
                logger.info("Successfully uploaded archive to s3://%s/%s", self.bucket, s3_key)
                return s3_key, local_temp_path
            except Exception as e:
                logger.error("Failed to upload archive to S3: %s", str(e))
                # If S3 upload fails, remove local file and raise error
                if os.path.exists(local_temp_path):
                    os.remove(local_temp_path)
                raise RuntimeError("Cloud storage upload failed.") from e

        else:
            # Local storage backend
            user_dir = os.path.join(self.local_dir, str(user_id))
            os.makedirs(user_dir, exist_ok=True)
            local_path = os.path.join(user_dir, safe_filename)
            file_storage.seek(0)
            file_storage.save(local_path)
            return local_path, local_path

    def cleanup_archive(self, s3_key: str = None, local_path: str = None):
        """Removes local temporary files and optionally S3 object according to retention."""
        if local_path and os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass

        # In cloud mode, default policy retains or deletes as configured
        if s3_key and self.backend == "s3" and current_app.config.get("DELETE_S3_AFTER_SCAN", False):
            try:
                import boto3
                s3_client = boto3.client("s3", region_name=self.region)
                s3_client.delete_object(Bucket=self.bucket, Key=s3_key)
            except Exception as e:
                logger.warning("Could not delete S3 object %s: %s", s3_key, str(e))

