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


def test_register_success(client):
    res = client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    assert "token" in data["data"]
    assert data["data"]["user"]["email"] == "alice@example.com"
    # Never return password hash!
    assert "password_hash" not in data["data"]["user"]


def test_register_duplicate_email(client):
    client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    res = client.post("/api/auth/register", json={
        "name": "Alice Dev Duplicate",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 409
    data = res.get_json()
    assert data["success"] is False


def test_register_validation(client):
    # Short password
    res = client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "short"
    })
    assert res.status_code == 400

    # Invalid email
    res2 = client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "invalid-email",
        "password": "Password123!"
    })
    assert res2.status_code == 400


def test_login_success(client):
    client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    res = client.post("/api/auth/login", json={
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "token" in data["data"]


def test_login_invalid_password(client):
    client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    res = client.post("/api/auth/login", json={
        "email": "alice@example.com",
        "password": "WrongPassword!"
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data["success"] is False


def test_me_protected_route(client):
    # Unauthenticated
    res = client.get("/api/auth/me")
    assert res.status_code == 401

    # Authenticated via Bearer token
    reg = client.post("/api/auth/register", json={
        "name": "Alice Dev",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    token = reg.get_json()["data"]["token"]
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["data"]["user"]["email"] == "alice@example.com"

