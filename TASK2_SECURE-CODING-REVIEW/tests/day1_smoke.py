"""Day 1 smoke test — runs against TestClient (no server required)."""
import sys
import os

# Ensure backend app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app.main import app
from app.models import Base, Scan
from app.database import engine


def run():
    # Recreate tables fresh (uses SQLite fallback in .env)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Verify Scan table has created_at column
    cols = [c.name for c in Scan.__table__.columns]
    assert "created_at" in cols, f"created_at missing from Scan! cols={cols}"
    print(f"PASS: Scan.created_at present. Columns: {cols}")

    client = TestClient(app)

    # Health
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}, r.text
    print("PASS: /api/health OK")

    # Signup
    r = client.post("/api/auth/signup", json={"email": "day1@codesentry.dev", "password": "SecurePass123!"})
    assert r.status_code == 201, f"signup failed: {r.text}"
    print("PASS: signup 201")

    # Duplicate signup should be 409
    r = client.post("/api/auth/signup", json={"email": "day1@codesentry.dev", "password": "SecurePass123!"})
    assert r.status_code == 409, f"duplicate signup should be 409, got {r.status_code}: {r.text}"
    print("PASS: duplicate signup correctly returns 409")

    # Login
    r = client.post("/api/auth/login", data={"username": "day1@codesentry.dev", "password": "SecurePass123!"})
    assert r.status_code == 200, f"login failed: {r.text}"
    token = r.json()["access_token"]
    print("PASS: login 200, got token")

    headers = {"Authorization": f"Bearer {token}"}

    # Dashboard (empty)
    r = client.get("/api/dashboard", headers=headers)
    assert r.status_code == 200, f"dashboard failed: {r.text}"
    data = r.json()
    assert data["total_projects"] == 0
    assert data["total_findings"] == 0
    print(f"PASS: dashboard returns empty summary: {data}")

    # Create git project with valid URL
    r = client.post("/api/projects", json={
        "name": "Test Project",
        "source_type": "git",
        "source_ref": "https://github.com/test/repo.git",
    }, headers=headers)
    assert r.status_code == 201, f"project create failed: {r.text}"
    project_id = r.json()["id"]
    print(f"PASS: project created: {project_id}")

    # List projects
    r = client.get("/api/projects", headers=headers)
    assert r.status_code == 200 and len(r.json()) == 1, r.text
    print("PASS: project list returns 1 project")

    # SSRF: block private IP git URL
    r = client.post("/api/projects", json={
        "name": "SSRF attempt",
        "source_type": "git",
        "source_ref": "https://192.168.1.1/evil.git",
    }, headers=headers)
    assert r.status_code == 400, f"Should have blocked private IP, got {r.status_code}: {r.text}"
    print(f"PASS: private IP git URL blocked 400: {r.json().get('detail')}")

    # SSRF: block AWS metadata endpoint
    r = client.post("/api/projects", json={
        "name": "SSRF attempt 2",
        "source_type": "git",
        "source_ref": "https://169.254.169.254/latest/meta-data",
    }, headers=headers)
    assert r.status_code == 400, f"Should have blocked metadata IP, got {r.status_code}: {r.text}"
    print(f"PASS: AWS metadata IP blocked 400: {r.json().get('detail')}")

    # IDOR: unauthenticated access blocked
    r = client.get(f"/api/projects/{project_id}")
    assert r.status_code == 401, f"Unauthenticated access should be 401, got {r.status_code}"
    print("PASS: unauthenticated project access returns 401")

    # Delete project
    r = client.delete(f"/api/projects/{project_id}", headers=headers)
    assert r.status_code == 204, f"delete failed: {r.text}"
    print("PASS: project deleted 204")

    print()
    print("=" * 50)
    print("All Day 1 smoke tests PASSED.")
    print("=" * 50)


if __name__ == "__main__":
    run()
