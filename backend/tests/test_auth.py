import uuid
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_register_then_login():
    email = f"test_{uuid.uuid4().hex}@example.com"
    password = "password123"

    r1 = client.post("/auth/register", json={"email": email, "password": password})
    assert r1.status_code == 200
    assert "access_token" in r1.json()

    r2 = client.post("/auth/login", json={"email": email, "password": password})
    assert r2.status_code == 200
    assert "access_token" in r2.json()