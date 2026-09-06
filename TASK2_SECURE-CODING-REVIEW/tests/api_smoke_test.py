"""Smoke test for CodeSentry backend API."""
import requests

BASE = "http://127.0.0.1:8000"


def main():
    # Login
    r = requests.post(f"{BASE}/api/auth/login", data={
        "username": "test@example.com",
        "password": "SecurePass123!",
    })
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # List projects
    r = requests.get(f"{BASE}/api/projects", headers=headers)
    assert r.status_code == 200, r.text
    projects = r.json()
    assert len(projects) > 0
    project_id = projects[0]["id"]

    # Trigger scan
    r = requests.post(f"{BASE}/api/scans/project/{project_id}", headers=headers)
    assert r.status_code == 201, r.text
    scan = r.json()
    print("Scan created:", scan["id"], "status:", scan["status"])

    # Get scan
    r = requests.get(f"{BASE}/api/scans/{scan['id']}", headers=headers)
    assert r.status_code == 200, r.text
    print("Scan status:", r.json()["status"])

    # List findings (likely empty without worker)
    r = requests.get(f"{BASE}/api/findings/scan/{scan['id']}", headers=headers)
    assert r.status_code == 200, r.text
    print("Findings count:", len(r.json()))

    print("Smoke test passed.")


if __name__ == "__main__":
    main()
