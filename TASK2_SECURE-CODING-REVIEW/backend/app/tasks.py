import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from celery import Celery
from celery.exceptions import OperationalError as CeleryOperationalError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import Finding, Project, Scan, ScanArtifact, ScanStatus, ArtifactType, SourceType
from app.services.normalizer import ensure_rules, normalize_osv, normalize_semgrep
from app.services.storage import cleanup_path, ensure_dir

settings = get_settings()
celery_app = Celery("codesentry", broker=settings.redis_url, backend=settings.redis_url)


def _update_scan_status(scan_id: str, status: ScanStatus, error: str = None) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = status
        if status in {ScanStatus.scanning_sast, ScanStatus.cloning} and not scan.started_at:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.complete, ScanStatus.failed}:
            scan.completed_at = datetime.now(timezone.utc)
        if error:
            scan.error_message = error
        db.commit()
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=1, default_retry_delay=10)
def run_scan(self, scan_id: str) -> dict:
    settings = get_settings()
    _update_scan_status(scan_id, ScanStatus.queued)

    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")
        project = scan.project
    finally:
        db.close()

    artifact_dir = ensure_dir(settings.artifacts_dir)
    work_dir = ensure_dir(os.path.join(artifact_dir, f"scan-{scan_id}"))
    semgrep_output = os.path.join(work_dir, "semgrep.json")
    osv_output = os.path.join(work_dir, "osv.json")

    try:
        _update_scan_status(scan_id, ScanStatus.cloning)

        cmd = [
            "docker", "run", "--rm",
            "--memory", settings.scan_memory_limit,
            "--cpus", str(settings.scan_cpu_limit),
            "--read-only",
            "-v", f"{work_dir}:/workspace/out",
            "-e", f"SCAN_ID={scan_id}",
            "-e", f"PROJECT_SOURCE_TYPE={project.source_type.value}",
            "-e", f"PROJECT_SOURCE_REF={project.source_ref}",
        ]

        if project.source_type == SourceType.upload:
            source_mount = project.source_ref
            # The upload was extracted to a project-scoped directory.
            cmd.extend(["-v", f"{source_mount}:/workspace/source:ro"])
            cmd.extend(["--network", "none"])
        else:
            # Git clone requires network; validation occurs before this stage.
            pass

        cmd.append("codesentry-worker")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Scan worker failed: {result.stderr}")

        _persist_artifacts_and_findings(scan_id, semgrep_output, osv_output, db=None)
        _update_scan_status(scan_id, ScanStatus.complete)
        return {"scan_id": scan_id, "status": "complete"}

    except subprocess.TimeoutExpired:
        _update_scan_status(scan_id, ScanStatus.failed, "Scan timed out")
        raise self.retry(exc=TimeoutError("Scan timed out"))
    except Exception as exc:
        _update_scan_status(scan_id, ScanStatus.failed, str(exc))
        raise self.retry(exc=exc)
    finally:
        # Keep work_dir for artifact reproducibility; do not delete.
        pass


def _persist_artifacts_and_findings(
    scan_id: str,
    semgrep_path: str,
    osv_path: str,
    db: Session = None,
) -> None:
    close_db = db is None
    if db is None:
        db = SessionLocal()
    try:
        if os.path.exists(semgrep_path):
            db.add(ScanArtifact(
                scan_id=scan_id,
                type=ArtifactType.raw_semgrep_json,
                storage_path=semgrep_path,
            ))
        if os.path.exists(osv_path):
            db.add(ScanArtifact(
                scan_id=scan_id,
                type=ArtifactType.raw_osv_json,
                storage_path=osv_path,
            ))

        semgrep_findings = normalize_semgrep(semgrep_path)
        osv_findings = normalize_osv(osv_path)
        all_findings: List[Finding] = semgrep_findings + osv_findings

        ensure_rules(db, all_findings)

        for finding in all_findings:
            finding.scan_id = scan_id
            db.add(finding)

        db.commit()
    finally:
        if close_db:
            db.close()
