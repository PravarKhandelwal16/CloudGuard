import io
import zipfile
import pytest
from backend.app import create_app
from backend.app.config import TestConfig
from backend.app.extensions import db


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


def register_and_get_token(client, email="dev@example.com"):
    res = client.post("/api/auth/register", json={
        "name": "Dev User",
        "email": email,
        "password": "Password123!"
    })
    return res.get_json()["data"]["token"]


def create_in_memory_zip(files: dict[str, str]) -> io.BytesIO:
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)
    mem.seek(0)
    return mem


def test_scan_and_dashboard_flow(client):
    token = register_and_get_token(client, "alice@test.com")
    headers = {"Authorization": f"Bearer {token}"}

    # Create dummy project ZIP
    zip_bytes = create_in_memory_zip({
        "config.py": (
            '# CloudGuard Dummy Demo Config\n'
            'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"\n'
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            'DATABASE_URL = "postgres://admin:SuperSecretPass123!@db.host.internal:5432/app"\n'
            'SESSION_UUID = "550e8400-e29b-41d4-a716-446655440000"\n'
        ),
        "README.md": "# Sample Project\nThis is a sample project for testing.\n"
    })

    # Upload and scan
    res = client.post(
        "/api/scans",
        data={"file": (zip_bytes, "demo_project.zip")},
        content_type="multipart/form-data",
        headers=headers
    )
    assert res.status_code == 201
    scan_data = res.get_json()["data"]

    assert scan_data["status"] == "completed"
    assert scan_data["files_scanned"] == 2
    assert scan_data["total_findings"] >= 3
    assert scan_data["security_score"] < 100
    assert scan_data["critical_count"] >= 2  # AWS secret + DB URI

    # Verify findings are masked
    findings = scan_data["findings"]
    for f in findings:
        assert "****" in f["masked_preview"]
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in f["masked_preview"]
        assert "SuperSecretPass123!" not in f["masked_preview"]
        assert f["detection_method"] in ["Rule", "ML", "Rule + ML"]

    scan_id = scan_data["id"]

    # Fetch scan by ID
    get_res = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.get_json()["data"]["id"] == scan_id

    # Test Dashboard summary
    dash_res = client.get("/api/dashboard/summary", headers=headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.get_json()["data"]
    assert dash_data["total_scans"] == 1
    assert dash_data["total_findings"] == scan_data["total_findings"]
    assert dash_data["critical_findings"] == scan_data["critical_count"]
    assert dash_data["latest_security_score"] == scan_data["security_score"]
    assert len(dash_data["recent_scans"]) == 1
    assert len(dash_data["recent_high_risk_findings"]) >= 1


def test_user_ownership_isolation(client):
    # User 1 creates a scan
    token1 = register_and_get_token(client, "user1@test.com")
    zip_bytes = create_in_memory_zip({"app.py": "print('hello')\n"})
    res1 = client.post(
        "/api/scans",
        data={"file": (zip_bytes, "u1_proj.zip")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token1}"}
    )
    scan_id = res1.get_json()["data"]["id"]

    # User 2 tries to access User 1's scan
    token2 = register_and_get_token(client, "user2@test.com")
    res2 = client.get(
        f"/api/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token2}"}
    )
    # Must be 403 Forbidden!
    assert res2.status_code == 403
    assert res2.get_json()["success"] is False


def test_invalid_upload_rejected(client):
    token = register_and_get_token(client, "upload_tester@test.com")
    # Upload text file instead of ZIP
    res = client.post(
        "/api/scans",
        data={"file": (io.BytesIO(b"not a zip"), "malicious.txt")},
        content_type="multipart/form-data",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 400
    assert "Only .zip archives are supported" in res.get_json()["message"]


def test_sample_project_zip_scan(client):
    from pathlib import Path
    token = register_and_get_token(client, "sample_tester@test.com")
    sample_zip = Path(__file__).resolve().parent.parent.parent / "sample-project.zip"
    assert sample_zip.exists()

    with open(sample_zip, "rb") as f:
        res = client.post(
            "/api/scans",
            data={"file": (f, "sample-project.zip")},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {token}"}
        )

    assert res.status_code == 201
    data = res.get_json()["data"]
    assert data["status"] == "completed"
    assert data["files_scanned"] >= 4
    assert data["critical_count"] >= 2  # AWS secret + DB URI + GitHub Token
    assert data["security_score"] < 50   # Critical risk detected
    # Ensure all findings are masked and methods recorded
    for f in data["findings"]:
        assert "****" in f["masked_preview"]
        assert f["detection_method"] in ["Rule", "ML", "Rule + ML"]


def test_clean_sample_project_zip_scan(client):
    from pathlib import Path
    token = register_and_get_token(client, "clean_tester@test.com")
    clean_zip = Path(__file__).resolve().parent.parent.parent / "clean-sample-project.zip"
    assert clean_zip.exists()

    with open(clean_zip, "rb") as f:
        res = client.post(
            "/api/scans",
            data={"file": (f, "clean-sample-project.zip")},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {token}"}
        )

    assert res.status_code == 201
    data = res.get_json()["data"]
    assert data["status"] == "completed"
    assert data["files_scanned"] == 6
    assert data["total_findings"] == 0
    assert data["critical_count"] == 0
    assert data["high_count"] == 0
    assert data["security_score"] == 100
    assert len(data["findings"]) == 0

