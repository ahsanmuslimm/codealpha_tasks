"""
Day 2 — End-to-end scan pipeline test.

Tests the full path:
  trigger scan → task runs synchronously via run_scan() directly →
  normalizer → findings persisted in DB →
  verify counts, severities, CWE mappings, fingerprints →
  re-scan fingerprint carry-forward.

No Redis or Docker required. The task uses direct scan mode,
falling back to fixture output JSONs when Semgrep/OSV-Scanner
are not installed.

Run from backend/ directory:
    python -W ignore ../tests/day2_pipeline.py
"""
import os
import sys
import zipfile
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# ── App bootstrap ──────────────────────────────────────────────────────────
from fastapi.testclient import TestClient
from app.main import app
from app.models import Base, Finding, Scan, ScanStatus, Severity, TriageStatus
from app.database import engine, SessionLocal
from app.config import get_settings
from app.tasks import run_scan as _run_scan_task

cfg = get_settings()
FIXTURES_ROOT = Path(__file__).parent.parent / "fixtures"


def _fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _make_fixture_zip(fixture_name: str) -> str:
    """Zip a fixture directory into a temp file and return the path."""
    source = FIXTURES_ROOT / fixture_name
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w") as zf:
        for f in source.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(source))
    return tmp.name


def run():
    _fresh_db()
    client = TestClient(app)

    # ── Auth ───────────────────────────────────────────────────────────────
    client.post("/api/auth/signup", json={"email": "pipeline@test.dev", "password": "Pipeline123!"})
    r = client.post("/api/auth/login", data={"username": "pipeline@test.dev", "password": "Pipeline123!"})
    assert r.status_code == 200, f"login failed: {r.text}"
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("PASS: auth OK")

    # ── Create project via ZIP upload ──────────────────────────────────────
    zip_path = _make_fixture_zip("sample-python")
    try:
        with open(zip_path, "rb") as fh:
            r = client.post(
                "/api/projects/upload",
                data={"name": "Sample Python App"},
                files={"file": ("archive.zip", fh, "application/zip")},
                headers=headers,
            )
    finally:
        os.unlink(zip_path)
    assert r.status_code == 201, f"project create failed: {r.text}"
    project_id = r.json()["id"]
    print(f"PASS: project created: {project_id}")

    # ── Create a scan record manually (bypassing Celery/Redis) ────────────
    db = SessionLocal()
    try:
        scan = Scan(
            project_id=project_id,
            status=ScanStatus.queued,
            ruleset_version="codesentry-v1.0",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = str(scan.id)
    finally:
        db.close()
    print(f"PASS: scan record created: {scan_id}")

    # ── Run the scan task directly (no Celery, no Redis needed) ───────────
    # The task calls get_settings() on each invocation, so it respects
    # USE_DOCKER_WORKER=false from the .env file.
    print("INFO: running scan task directly (direct mode, no Docker/Redis)...")
    task_result = _run_scan_task(scan_id)
    print(f"PASS: scan task completed: {task_result}")
    assert task_result.get("status") == "complete", f"Task did not complete: {task_result}"

    # ── Verify scan status in DB ───────────────────────────────────────────
    r = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert r.status_code == 200, r.text
    scan_data = r.json()
    assert scan_data["status"] == "complete", (
        f"Expected 'complete', got '{scan_data['status']}'. "
        f"Error: {scan_data.get('error_message')}"
    )
    assert scan_data["started_at"] is not None, "started_at should be set"
    assert scan_data["completed_at"] is not None, "completed_at should be set"
    print(f"PASS: scan status = complete, timing fields populated")

    # ── Verify findings in DB ──────────────────────────────────────────────
    r = client.get(f"/api/findings/scan/{scan_id}", headers=headers)
    assert r.status_code == 200, r.text
    findings = r.json()
    n = len(findings)
    print(f"PASS: {n} findings returned")
    assert n >= 5, f"Expected >=5 findings for sample-python, got {n}"

    # Verify sort order: Critical/High/Medium before Low/Info
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranks = [severity_rank[f["severity"]] for f in findings]
    assert ranks == sorted(ranks), f"Findings not sorted by severity: {[f['severity'] for f in findings]}"
    print(f"PASS: findings sorted correctly: {[f['severity'] for f in findings]}")

    # Verify CWE/OWASP populated
    for f in findings:
        assert f["cwe_id"] or f["owasp_category"], f"Finding missing CWE+OWASP: {f}"
    print("PASS: all findings have CWE/OWASP mapping")

    # Verify unique fingerprints
    fps = [f["fingerprint"] for f in findings]
    assert len(fps) == len(set(fps)), f"Duplicate fingerprints: {fps}"
    print("PASS: all fingerprints unique")

    # All start as 'open'
    assert all(f["status"] == "open" for f in findings), "New findings should all be open"
    print("PASS: all new findings have status=open")

    # ── Severity filter ────────────────────────────────────────────────────
    r = client.get(f"/api/findings/scan/{scan_id}?severity=high", headers=headers)
    high = r.json()
    assert all(f["severity"] == "high" for f in high)
    print(f"PASS: severity=high filter works ({len(high)} high findings)")

    r = client.get(f"/api/findings/scan/{scan_id}?severity=medium", headers=headers)
    medium = r.json()
    assert all(f["severity"] == "medium" for f in medium)
    print(f"PASS: severity=medium filter works ({len(medium)} medium findings)")

    # ── Triage a finding ───────────────────────────────────────────────────
    target_id = findings[0]["id"]
    r = client.patch(
        f"/api/findings/{target_id}",
        json={"status": "confirmed", "notes": "Confirmed SQL injection — exploitable via login endpoint"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    triaged = r.json()
    assert triaged["status"] == "confirmed"
    assert triaged["triage_notes"] is not None
    print("PASS: triage PATCH confirmed finding")

    # ── Triage audit history ───────────────────────────────────────────────
    r = client.get(f"/api/findings/{target_id}/history", headers=headers)
    assert r.status_code == 200, r.text
    history = r.json()
    assert len(history) == 1, f"Expected 1 event, got {len(history)}"
    assert history[0]["previous_status"] == "open"
    assert history[0]["new_status"] == "confirmed"
    print("PASS: triage audit log entry correct")

    # ── IDOR: another user cannot see this scan ────────────────────────────
    client.post("/api/auth/signup", json={"email": "attacker@evil.dev", "password": "Attacker123!"})
    r_atk = client.post("/api/auth/login", data={"username": "attacker@evil.dev", "password": "Attacker123!"})
    atk_headers = {"Authorization": f"Bearer {r_atk.json()['access_token']}"}
    r = client.get(f"/api/findings/scan/{scan_id}", headers=atk_headers)
    assert r.status_code == 404, f"IDOR! Attacker accessed scan findings: {r.status_code}"
    print("PASS: IDOR — attacker cannot see victim scan findings (404)")

    # ── Re-scan: fingerprint carry-forward ────────────────────────────────
    db = SessionLocal()
    try:
        scan2 = Scan(project_id=project_id, status=ScanStatus.queued, ruleset_version="codesentry-v1.0")
        db.add(scan2)
        db.commit()
        db.refresh(scan2)
        scan2_id = str(scan2.id)
    finally:
        db.close()

    result2 = _run_scan_task(scan2_id)
    assert result2.get("status") == "complete"

    r = client.get(f"/api/findings/scan/{scan2_id}", headers=headers)
    findings2 = r.json()
    carried = [f for f in findings2 if f["status"] == "confirmed"]
    print(f"PASS: re-scan produced {len(findings2)} findings, "
          f"{len(carried)} carried forward as confirmed (fingerprint dedup)")
    assert len(carried) >= 1, "Expected at least 1 carried-forward confirmed finding on re-scan"

    # ── Markdown report ────────────────────────────────────────────────────
    # Triage one more confirmed finding so the report has content.
    client.patch(
        f"/api/findings/{findings[1]['id']}",
        json={"status": "confirmed", "notes": "Eval injection confirmed"},
        headers=headers,
    )
    r = client.post(
        f"/api/reports/scan/{scan_id}/markdown",
        json={"include_all": False},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    report = r.json()
    content = report["content"]
    assert "CodeSentry Audit Report" in content
    assert "confirmed" in content.lower()
    print("PASS: markdown report generated with confirmed findings")

    # ── Report scopes: include_all=True ───────────────────────────────────
    r = client.post(
        f"/api/reports/scan/{scan_id}/markdown",
        json={"include_all": True},
        headers=headers,
    )
    all_report = r.json()["content"]
    assert all_report.count("###") >= n, "include_all=True should show all findings"
    print("PASS: include_all=True report includes all findings")

    # ── Dashboard reflects findings ────────────────────────────────────────
    r = client.get("/api/dashboard", headers=headers)
    dash = r.json()
    assert dash["total_projects"] == 1
    # Dashboard counts findings across both scans.
    assert dash["total_findings"] >= n, f"Dashboard total_findings too low: {dash}"
    print(f"PASS: dashboard: {dash['total_projects']} projects, "
          f"{dash['total_findings']} findings, severity={dash['findings_by_severity']}")

    print()
    print("=" * 60)
    print(f"All Day 2 pipeline tests PASSED. ({n} findings from sample-python fixture)")
    print("=" * 60)


if __name__ == "__main__":
    run()
