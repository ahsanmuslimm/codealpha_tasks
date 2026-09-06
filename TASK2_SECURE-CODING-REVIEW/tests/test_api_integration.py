"""
Integration tests for CodeSentry backend API.
Tests the full flow: project creation → scan trigger → findings normalization.
Run with: pytest tests/test_api_integration.py -v
"""
import os
import sys
import tempfile
import json
from pathlib import Path
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.models import User, Project, SourceType, Scan, ScanStatus, Finding
from app.main import app
from app.auth import hash_password
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def db_engine():
    """Use an in-memory SQLite database for tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    """Create a fresh session for each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(autocommit=False, autoflush=False, bind=connection)()

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """FastAPI test client with DB override."""
    return TestClient(app)


@pytest.fixture
def test_user(db_session):
    """Create a test user."""
    user = User(
        id=str(uuid.uuid4()),
        email="test@example.com",
        password_hash=hash_password("testpassword123"),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(client):
    """Login and return authorization headers."""
    # Signup
    client.post("/api/auth/signup", json={
        "email": "testuser@example.com",
        "password": "testpass12345",
    })
    # Login
    response = client.post("/api/auth/login", data={
        "username": "testuser@example.com",
        "password": "testpass12345",
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestAuth:
    def test_signup_and_login(self, client):
        # Signup
        res = client.post("/api/auth/signup", json={
            "email": "newuser@example.com",
            "password": "securepass123",
        })
        assert res.status_code == 201
        assert res.json()["email"] == "newuser@example.com"

        # Login
        res = client.post("/api/auth/login", data={
            "username": "newuser@example.com",
            "password": "securepass123",
        })
        assert res.status_code == 200
        assert "access_token" in res.json()

    def test_login_wrong_password(self, client):
        client.post("/api/auth/signup", json={
            "email": "user@example.com",
            "password": "correctpass123",
        })
        res = client.post("/api/auth/login", data={
            "username": "user@example.com",
            "password": "wrongpass",
        })
        assert res.status_code == 401

    def test_me_requires_auth(self, client):
        res = client.get("/api/auth/me")
        assert res.status_code == 401


class TestProjects:
    def test_create_project_git(self, client, auth_headers):
        res = client.post(
            "/api/projects",
            json={
                "name": "OWASP Juice Shop",
                "source_type": "git",
                "source_ref": "https://github.com/bkimminich/juice-shop.git",
            },
            headers=auth_headers,
        )
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == "OWASP Juice Shop"
        assert data["source_type"] == "git"

    def test_create_project_git_blocks_private_ip(self, client, auth_headers):
        res = client.post(
            "/api/projects",
            json={
                "name": "Private",
                "source_type": "git",
                "source_ref": "https://192.168.1.1/repo.git",
            },
            headers=auth_headers,
        )
        assert res.status_code == 400
        assert "private" in res.json()["detail"].lower()

    def test_list_projects_own_only(self, client, auth_headers, db_session, test_user):
        # Create a project for test_user
        project = Project(
            id=str(uuid.uuid4()),
            owner_id=test_user.id,
            name="My Project",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project)
        db_session.commit()

        # Login as different user
        client.post("/api/auth/signup", json={
            "email": "other@example.com",
            "password": "pass12345",
        })
        res_login = client.post("/api/auth/login", data={
            "username": "other@example.com",
            "password": "pass12345",
        })
        other_headers = {"Authorization": f"Bearer {res_login.json()['access_token']}"}

        # Other user should not see test_user's project
        res = client.get("/api/projects", headers=other_headers)
        assert res.status_code == 200
        assert len(res.json()) == 0

    def test_delete_project(self, client, auth_headers):
        # Create
        res = client.post(
            "/api/projects",
            json={
                "name": "Delete Me",
                "source_type": "git",
                "source_ref": "https://github.com/example/repo.git",
            },
            headers=auth_headers,
        )
        project_id = res.json()["id"]

        # Delete
        res = client.delete(f"/api/projects/{project_id}", headers=auth_headers)
        assert res.status_code == 204

        # Verify deleted
        res = client.get(f"/api/projects/{project_id}", headers=auth_headers)
        assert res.status_code == 404


class TestScans:
    def test_trigger_scan_requires_auth(self, client):
        res = client.post("/api/scans/project/nonexistent")
        assert res.status_code == 401

    def test_trigger_scan_not_found(self, client, auth_headers):
        res = client.post("/api/scans/project/nonexistent", headers=auth_headers)
        assert res.status_code == 404

    def test_trigger_scan_creates_queued_scan(self, client, auth_headers, db_session, test_user):
        # Create project
        project = Project(
            id=str(uuid.uuid4()),
            owner_id=test_user.id,
            name="Test Project",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project)
        db_session.commit()

        # Trigger scan (won't actually run without Celery)
        res = client.post(
            f"/api/scans/project/{project.id}",
            headers=auth_headers,
        )
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "queued"
        assert data["project_id"] == project.id


class TestFindings:
    def test_findings_list_requires_auth(self, client):
        res = client.get("/api/findings/scan/nonexistent")
        assert res.status_code == 401

    def test_findings_empty_scan(self, client, auth_headers, db_session, test_user):
        project = Project(
            id=str(uuid.uuid4()),
            owner_id=test_user.id,
            name="Test",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project)
        db_session.commit()

        scan = Scan(
            id=str(uuid.uuid4()),
            project_id=project.id,
            status=ScanStatus.complete,
        )
        db_session.add(scan)
        db_session.commit()

        res = client.get(f"/api/findings/scan/{scan.id}", headers=auth_headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_findings_filter_by_severity(self, client, auth_headers, db_session, test_user):
        from app.models import Finding, Severity, TriageStatus, Rule, RuleSource

        project = Project(
            id=str(uuid.uuid4()),
            owner_id=test_user.id,
            name="Test",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project)
        db_session.commit()

        scan = Scan(
            id=str(uuid.uuid4()),
            project_id=project.id,
            status=ScanStatus.complete,
        )
        db_session.add(scan)
        db_session.commit()

        # Add rule
        rule = Rule(
            id="test:rule1",
            source=RuleSource.semgrep,
            description="Test rule",
            default_severity=Severity.critical,
        )
        db_session.add(rule)
        db_session.commit()

        # Add critical and low findings
        for severity, line in [(Severity.critical, 1), (Severity.low, 2)]:
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                rule_id=rule.id,
                severity=severity,
                file_path="test.py",
                line_start=line,
                description="Test",
                fingerprint="fp" + str(line),
                status=TriageStatus.open,
            )
            db_session.add(finding)
        db_session.commit()

        # Filter for critical only
        res = client.get(
            f"/api/findings/scan/{scan.id}",
            params={"severity": "critical"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        findings = res.json()
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


class TestDashboard:
    def test_dashboard_summary(self, client, auth_headers):
        res = client.get("/api/dashboard", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert "total_projects" in data
        assert "total_findings" in data
        assert "findings_by_severity" in data


class TestReports:
    def test_markdown_report_confirmed_only(self, client, auth_headers, db_session, test_user):
        from app.models import Finding, Severity, TriageStatus, Rule, RuleSource

        project = Project(
            id=str(uuid.uuid4()),
            owner_id=test_user.id,
            name="Test",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project)
        db_session.commit()

        scan = Scan(
            id=str(uuid.uuid4()),
            project_id=project.id,
            status=ScanStatus.complete,
            ruleset_version="v1",
        )
        db_session.add(scan)
        db_session.commit()

        rule = Rule(
            id="test:sql-injection",
            source=RuleSource.semgrep,
            description="SQL Injection",
            default_severity=Severity.critical,
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
        )
        db_session.add(rule)
        db_session.commit()

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            rule_id=rule.id,
            severity=Severity.critical,
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            file_path="app.py",
            line_start=42,
            code_snippet="user_input = request.args.get('id')\ndb.execute(f'SELECT * FROM users WHERE id={user_input}')",
            description="SQL injection vulnerability",
            remediation="Use parameterized queries",
            fingerprint="abc123",
            status=TriageStatus.confirmed,
            triage_notes="Confirmed - high risk",
        )
        db_session.add(finding)
        db_session.commit()

        res = client.post(
            f"/api/reports/scan/{scan.id}/markdown",
            json={"include_all": False},
            headers=auth_headers,
        )
        assert res.status_code == 200
        report = res.json()["content"]
        assert "SQL Injection" in report
        assert "CWE-89" in report
        assert "A03:2021" in report
        assert "Confirmed" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
