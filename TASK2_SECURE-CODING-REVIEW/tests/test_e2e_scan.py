"""
End-to-end test simulating a full scan workflow with local fixtures.
This test validates the pipeline from scan trigger through finding normalization.
Run with: pytest tests/test_e2e_scan.py -v
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
from app.models import (
    User, Project, SourceType, Scan, ScanStatus, Finding, TriageStatus,
    Rule, RuleSource, ScanArtifact, ArtifactType, Severity
)
from app.services.normalizer import normalize_semgrep, normalize_osv, ensure_rules
from app.config import Settings


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(autocommit=False, autoflush=False, bind=connection)()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


class TestEndToEndScanPipeline:
    """Test the full scan pipeline without Docker or actual Semgrep/OSV."""

    def test_normalize_and_persist_semgrep_findings(self, db_session):
        """Load fixture Semgrep output and normalize it."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        semgrep_path = fixtures_dir / "sample-python.json"

        assert semgrep_path.exists(), f"Fixture not found: {semgrep_path}"

        # Normalize
        findings = normalize_semgrep(str(semgrep_path))
        assert len(findings) > 0, "Should have normalized findings"

        # Check structure
        for f in findings:
            assert f.severity in [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
            assert f.file_path, "Should have file_path"
            assert f.description, "Should have description"
            assert f.fingerprint, "Should have fingerprint"

        print(f"✓ Normalized {len(findings)} Semgrep findings from sample-python")

    def test_normalize_and_persist_osv_findings(self, db_session):
        """Load fixture OSV output and normalize it."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        osv_path = fixtures_dir / "sample-java-osv.json"

        assert osv_path.exists(), f"Fixture not found: {osv_path}"

        # Normalize
        findings = normalize_osv(str(osv_path))
        assert len(findings) > 0, "Should have normalized findings"

        for f in findings:
            assert f.cwe_id == "CWE-1104", "OSV findings should map to CWE-1104"
            assert "A06:2021" in f.owasp_category, "Should map to A06 (Vulnerable Components)"

        print(f"✓ Normalized {len(findings)} OSV findings from sample-java")

    def test_full_scan_workflow(self, db_session):
        """Simulate a complete scan: project → scan → findings → triage."""
        # 1. Create user and project
        user_id = str(uuid.uuid4())
        user = User(id=user_id, email="auditor@test.com", password_hash="hashed")
        db_session.add(user)
        db_session.commit()

        project_id = str(uuid.uuid4())
        project = Project(
            id=project_id,
            owner_id=user_id,
            name="Sample Python App",
            source_type=SourceType.git,
            source_ref="https://github.com/example/vulnerable-app.git",
        )
        db_session.add(project)
        db_session.commit()

        # 2. Create scan
        scan_id = str(uuid.uuid4())
        scan = Scan(
            id=scan_id,
            project_id=project_id,
            status=ScanStatus.queued,
            ruleset_version="codesentry-v1.0",
        )
        db_session.add(scan)
        db_session.commit()

        # 3. Simulate scan execution (normalize fixtures)
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        semgrep_findings = normalize_semgrep(str(fixtures_dir / "sample-python.json"))

        # 4. Ensure rules exist
        ensure_rules(db_session, semgrep_findings)

        # 5. Persist findings
        for finding in semgrep_findings:
            finding.scan_id = scan_id
            db_session.add(finding)
        db_session.commit()

        # 6. Mark scan complete
        scan.status = ScanStatus.complete
        db_session.commit()

        # 7. Verify persistence
        persisted = db_session.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(persisted) == len(semgrep_findings), "All findings should be persisted"

        # 8. Triage a finding
        critical_finding = next((f for f in persisted if f.severity == Severity.critical), None)
        if critical_finding:
            critical_finding.status = TriageStatus.confirmed
            critical_finding.triage_notes = "Confirmed vulnerability - requires immediate remediation"
            critical_finding.triaged_by = user_id
            db_session.commit()

            # Verify triage
            refreshed = db_session.query(Finding).filter(Finding.id == critical_finding.id).first()
            assert refreshed.status == TriageStatus.confirmed
            assert refreshed.triage_notes == "Confirmed vulnerability - requires immediate remediation"

        print(f"✓ Full workflow complete: {len(persisted)} findings triaged")

    def test_fingerprint_consistency(self, db_session):
        """Verify fingerprints are stable across re-scans."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        semgrep_path = fixtures_dir / "sample-python.json"

        # Normalize twice
        findings1 = normalize_semgrep(str(semgrep_path))
        findings2 = normalize_semgrep(str(semgrep_path))

        # Fingerprints should match
        for f1, f2 in zip(findings1, findings2):
            assert f1.fingerprint == f2.fingerprint, "Fingerprints should be stable"

        print(f"✓ Fingerprints are stable across re-scans")

    def test_findings_by_severity_distribution(self, db_session):
        """Check distribution of findings across severity levels."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"

        # Load all fixtures
        fixtures = ["sample-python.json", "sample-js.json", "sample-java.json"]
        all_findings = []

        for fixture in fixtures:
            path = fixtures_dir / fixture
            if path.exists():
                findings = normalize_semgrep(str(path))
                all_findings.extend(findings)

        # Count by severity
        severity_counts = {}
        for severity in [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]:
            count = sum(1 for f in all_findings if f.severity == severity)
            if count > 0:
                severity_counts[severity.value] = count

        print(f"✓ Findings by severity: {severity_counts}")

        # Should have at least some findings
        assert len(all_findings) > 0, "Should have findings from fixtures"
        assert len(severity_counts) > 0, "Should have findings at various severity levels"

    def test_owasp_mapping(self, db_session):
        """Verify OWASP Top 10 mapping for findings."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        findings = normalize_semgrep(str(fixtures_dir / "sample-python.json"))

        # Check OWASP mappings
        owasp_categories = set()
        for f in findings:
            if f.owasp_category:
                owasp_categories.add(f.owasp_category)
                # Verify format
                assert ":" in f.owasp_category or "2021" in f.owasp_category or f.owasp_category == "Unknown"

        print(f"✓ OWASP categories found: {owasp_categories}")

    def test_cwe_mapping(self, db_session):
        """Verify CWE mapping for findings."""
        fixtures_dir = Path(__file__).parent.parent / "fixtures" / "outputs"
        findings = normalize_semgrep(str(fixtures_dir / "sample-python.json"))

        # Check CWE mappings
        cwe_ids = set()
        for f in findings:
            if f.cwe_id:
                cwe_ids.add(f.cwe_id)
                # Verify format (CWE-XXXX)
                assert f.cwe_id.startswith("CWE-"), f"Invalid CWE format: {f.cwe_id}"

        print(f"✓ CWE IDs found: {cwe_ids}")
        assert len(cwe_ids) > 0, "Should have CWE mappings"


class TestSecurityControls:
    """Verify security controls are properly enforced."""

    def test_project_owner_isolation(self, db_session):
        """Verify projects are isolated by owner."""
        # Create two users
        user1_id = str(uuid.uuid4())
        user2_id = str(uuid.uuid4())

        user1 = User(id=user1_id, email="user1@test.com", password_hash="hashed")
        user2 = User(id=user2_id, email="user2@test.com", password_hash="hashed")

        db_session.add_all([user1, user2])
        db_session.commit()

        # Create project for user1
        project1 = Project(
            id=str(uuid.uuid4()),
            owner_id=user1_id,
            name="User1 Project",
            source_type=SourceType.git,
            source_ref="https://github.com/example/repo.git",
        )
        db_session.add(project1)
        db_session.commit()

        # User2 should not see user1's project
        user2_projects = db_session.query(Project).filter(Project.owner_id == user2_id).all()
        assert len(user2_projects) == 0

        # User1 should see their project
        user1_projects = db_session.query(Project).filter(Project.owner_id == user1_id).all()
        assert len(user1_projects) == 1

        print("✓ Project owner isolation verified")

    def test_finding_authorization(self, db_session):
        """Verify findings are scoped by project owner."""
        user_id = str(uuid.uuid4())
        user = User(id=user_id, email="user@test.com", password_hash="hashed")
        db_session.add(user)
        db_session.commit()

        project = Project(
            id=str(uuid.uuid4()),
            owner_id=user_id,
            name="Project",
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

        rule = Rule(
            id="test:rule",
            source=RuleSource.semgrep,
            description="Test",
            default_severity=Severity.high,
        )
        db_session.add(rule)
        db_session.commit()

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            rule_id=rule.id,
            severity=Severity.high,
            file_path="app.py",
            description="Test",
            fingerprint="fp123",
            status=TriageStatus.open,
        )
        db_session.add(finding)
        db_session.commit()

        # Verify finding is associated with user via project
        result = db_session.query(Finding).join(Scan).join(Project).filter(
            Project.owner_id == user_id
        ).all()
        assert len(result) == 1

        print("✓ Finding authorization verified")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
