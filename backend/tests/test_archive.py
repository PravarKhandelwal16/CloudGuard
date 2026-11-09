import os
import io
import zipfile
import tempfile
import pytest
from backend.app.services.archive_service import ArchiveService, ArchiveValidationError


@pytest.fixture
def archive_service():
    config = {
        "MAX_ARCHIVE_FILES": 10,
        "MAX_ARCHIVE_UNCOMPRESSED_BYTES": 1024 * 1024,  # 1MB
        "PER_FILE_MAX_BYTES": 100 * 1024  # 100KB
    }
    return ArchiveService(config=config)


def create_zip_file(entries: dict[str, bytes], password: bytes = None) -> str:
    """Helper to create a temporary zip file."""
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        if password:
            zf.setpassword(password)
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_valid_zip_extracted(archive_service):
    zip_path = create_zip_file({
        "app.py": b"print('hello world')\n",
        "config.json": b'{"key": "value"}\n',
        "Dockerfile": b"FROM python:3.11\n"
    })
    try:
        extract_dir = archive_service.extract_safely(zip_path)
        assert os.path.isdir(extract_dir)
        scannable, scanned, skipped, _ = archive_service.get_scannable_files(extract_dir)
        assert scanned == 3
        assert skipped == 0
        assert len(scannable) == 3
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_non_zip_rejected(archive_service):
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.write(fd, b"This is not a zip file content.")
    os.close(fd)
    try:
        with pytest.raises(ArchiveValidationError, match="not a valid ZIP archive"):
            archive_service.extract_safely(path)
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_corrupt_zip_rejected(archive_service):
    fd, path = tempfile.mkstemp(suffix=".zip")
    # Write PK header followed by garbage
    os.write(fd, b"PK\x03\x04corrupted_payload_without_central_directory")
    os.close(fd)
    try:
        with pytest.raises(ArchiveValidationError):
            archive_service.extract_safely(path)
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_excessive_files_rejected(archive_service):
    # Max files is 10 in fixture
    entries = {f"file_{i}.txt": b"content" for i in range(15)}
    zip_path = create_zip_file(entries)
    try:
        with pytest.raises(ArchiveValidationError, match="exceeds maximum allowed entry count"):
            archive_service.extract_safely(zip_path)
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_excessive_uncompressed_size_rejected(archive_service):
    # Max uncompressed is 1MB in fixture; create 2MB entry
    entries = {"large.txt": b"A" * (2 * 1024 * 1024)}
    zip_path = create_zip_file(entries)
    try:
        with pytest.raises(ArchiveValidationError, match="exceeds maximum allowed uncompressed size"):
            archive_service.extract_safely(zip_path)
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_path_traversal_blocked(archive_service):
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("../../etc/passwd", b"malicious content")

    try:
        with pytest.raises(ArchiveValidationError, match="path traversal"):
            archive_service.extract_safely(path)
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_binary_and_excluded_files_skipped(archive_service):
    zip_path = create_zip_file({
        "src/app.py": b"print('valid')",
        "node_modules/lib.js": b"console.log('in node_modules')",
        ".git/config": b"[core]\nrepositoryformatversion = 0",
        "image.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",  # binary
        "data.bin": b"some text with null \x00 byte inside",
        "doc.pdf": b"%PDF-1.4 binary data",
    })
    try:
        extract_dir = archive_service.extract_safely(zip_path)
        scannable, scanned, skipped, details = archive_service.get_scannable_files(extract_dir)
        # Only src/app.py is scannable
        assert scanned == 1
        assert scannable[0][0] == "src/app.py"
        assert skipped == 5
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)

