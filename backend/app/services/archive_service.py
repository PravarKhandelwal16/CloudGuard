import os
import shutil
import zipfile
import tempfile
import logging
from pathlib import Path
from flask import current_app

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php",
    ".rb", ".cs", ".cpp", ".c", ".h", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".env", ".conf", ".config", ".properties",
    ".xml", ".sql", ".sh", ".bash", ".ps1", ".tf", ".md", ".txt"
}

ALLOWED_FILENAMES = {
    "dockerfile", "jenkinsfile", "vagrantfile", "makefile", "gemfile", "procfile"
}

EXCLUDED_DIR_NAMES = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist",
    "build", "target", ".idea", ".vscode", ".pytest_cache"
}


class ArchiveValidationError(Exception):
    """Raised when an uploaded archive fails security or format validation."""
    pass


class ArchiveService:
    """Safely inspects, validates, extracts, and filters project archives."""

    def __init__(self, config=None):
        self.max_files = (config or current_app.config).get("MAX_ARCHIVE_FILES", 1000)
        self.max_uncompressed_bytes = (config or current_app.config).get(
            "MAX_ARCHIVE_UNCOMPRESSED_BYTES", 100 * 1024 * 1024
        )
        self.per_file_max_bytes = (config or current_app.config).get(
            "PER_FILE_MAX_BYTES", 5 * 1024 * 1024
        )

    def validate_zip(self, zip_path: str):
        """Validates that zip_path is a valid, unencrypted, and within-limit ZIP archive."""
        if not os.path.exists(zip_path):
            raise ArchiveValidationError("Uploaded file does not exist.")

        if not zipfile.is_zipfile(zip_path):
            raise ArchiveValidationError("File is not a valid ZIP archive.")

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infos = zf.infolist()

                if len(infos) > self.max_files:
                    raise ArchiveValidationError(
                        f"Archive exceeds maximum allowed entry count ({self.max_files} files)."
                    )

                total_uncompressed = 0
                for info in infos:
                    # Check encryption flag
                    if info.flag_bits & 0x1:
                        raise ArchiveValidationError(
                            "Encrypted or password-protected archives are not supported."
                        )

                    total_uncompressed += info.file_size
                    if total_uncompressed > self.max_uncompressed_bytes:
                        raise ArchiveValidationError(
                            "Archive exceeds maximum allowed uncompressed size limit."
                        )

                    # Path traversal checks
                    filename = info.filename
                    if filename.startswith("/") or filename.startswith("\\"):
                        raise ArchiveValidationError(f"Archive entry contains an illegal absolute path: {filename}")
                    
                    # Check for drive letters like C:
                    if len(filename) > 1 and filename[1] == ":":
                        raise ArchiveValidationError(f"Archive entry contains an illegal path: {filename}")

                    parts = Path(filename).parts
                    if ".." in parts:
                        raise ArchiveValidationError(
                            f"Archive entry contains illegal path traversal component '..': {filename}"
                        )

        except zipfile.BadZipFile as e:
            raise ArchiveValidationError("Archive is corrupt or unreadable.") from e

    def extract_safely(self, zip_path: str) -> str:
        """
        Safely extracts ZIP contents to a newly created temporary directory.
        Enforces actual extracted bytes limit to prevent decompression bombs.
        Returns the temporary directory path.
        """
        self.validate_zip(zip_path)

        extract_dir = tempfile.mkdtemp(prefix="cloudguard_scan_")
        resolved_extract_dir = os.path.realpath(extract_dir)

        bytes_written = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for member in zf.infolist():
                    # Check symlinks (POSIX attribute bit 0o120000)
                    is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
                    if is_symlink:
                        # Ignore or skip symlinks for safety
                        continue

                    # Canonical path traversal defense
                    target_path = os.path.realpath(os.path.join(resolved_extract_dir, member.filename))
                    if not target_path.startswith(resolved_extract_dir + os.sep) and target_path != resolved_extract_dir:
                        raise ArchiveValidationError(f"Attempted path traversal detected: {member.filename}")

                    if member.is_dir():
                        os.makedirs(target_path, exist_ok=True)
                        continue

                    os.makedirs(os.path.dirname(target_path), exist_ok=True)

                    with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                        chunk_size = 64 * 1024
                        while True:
                            chunk = src.read(chunk_size)
                            if not chunk:
                                break
                            bytes_written += len(chunk)
                            if bytes_written > self.max_uncompressed_bytes:
                                raise ArchiveValidationError(
                                    "Archive exceeded uncompressed size limit during extraction."
                                )
                            dst.write(chunk)

            return extract_dir

        except Exception:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise

    def is_eligible_file(self, rel_path: str) -> tuple[bool, str]:
        """
        Determines if a relative file path is eligible for secret scanning.
        Returns (is_eligible, reason_if_skipped).
        """
        path_obj = Path(rel_path)
        parts = [p.lower() for p in path_obj.parts]

        # Check excluded directories
        for part in parts[:-1]:
            if part in EXCLUDED_DIR_NAMES:
                return False, f"excluded_directory:{part}"

        file_name = path_obj.name.lower()
        suffix = path_obj.suffix.lower()

        # Check filename allowlist or suffix allowlist
        if file_name in ALLOWED_FILENAMES or suffix in ALLOWED_EXTENSIONS:
            return True, ""

        # Allow files like .env.production, .env.local
        if file_name.startswith(".env"):
            return True, ""

        return False, f"unsupported_extension:{suffix or file_name}"

    def is_binary_file(self, full_path: str) -> bool:
        """Inspects first 8KB of file to check for null bytes or binary content."""
        try:
            with open(full_path, "rb") as f:
                header = f.read(8192)
                if b"\x00" in header:
                    return True
                # Check if it can be decoded with utf-8 or latin-1
                try:
                    header.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        header.decode("latin-1")
                    except UnicodeDecodeError:
                        return True
            return False
        except Exception:
            return True

    def get_scannable_files(self, extract_dir: str):
        """
        Walks the extracted directory and yields eligible text files.
        Yields:
            tuple: (rel_path, full_path)
        Returns counts in summary.
        """
        resolved_base = os.path.realpath(extract_dir)

        files_scanned = 0
        files_skipped = 0
        skipped_details = []
        scannable_files = []

        for root, dirs, files in os.walk(resolved_base):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, resolved_base).replace("\\", "/")

                eligible, skip_reason = self.is_eligible_file(rel_path)
                if not eligible:
                    files_skipped += 1
                    skipped_details.append((rel_path, skip_reason))
                    continue

                # Check file size limit
                try:
                    size = os.path.getsize(full_path)
                    if size > self.per_file_max_bytes:
                        files_skipped += 1
                        skipped_details.append((rel_path, "file_too_large"))
                        continue
                except OSError:
                    files_skipped += 1
                    continue

                # Check binary file
                if self.is_binary_file(full_path):
                    files_skipped += 1
                    skipped_details.append((rel_path, "binary_file"))
                    continue

                files_scanned += 1
                scannable_files.append((rel_path, full_path))

        return scannable_files, files_scanned, files_skipped, skipped_details

    def read_file_lines(self, full_path: str):
        """Reads file line by line with tolerant text decoding."""
        encodings = ["utf-8", "utf-8-sig", "latin-1"]
        content = None
        for enc in encodings:
            try:
                with open(full_path, "r", encoding=enc, errors="replace") as f:
                    content = f.readlines()
                break
            except Exception:
                continue

        if content is None:
            return []

        for line_num, line in enumerate(content, start=1):
            yield line_num, line
