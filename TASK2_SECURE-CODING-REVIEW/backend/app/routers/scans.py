from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Project, Scan, ScanStatus, User
from app.schemas import ScanOut
from app.tasks import run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _user_owns_project(project_id: str, user: User, db: Session) -> Project:
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == user.id,
    ).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


@router.post("/project/{project_id}", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = _user_owns_project(project_id, current_user, db)

    scan = Scan(
        project_id=project.id,
        status=ScanStatus.queued,
        ruleset_version="codesentry-v1.0",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        run_scan.delay(str(scan.id))
    except Exception as exc:
        # If the task broker (Redis) is unavailable, mark the scan failed immediately
        # rather than leaving it stuck in 'queued' forever.
        scan.status = ScanStatus.failed
        scan.error_message = f"Could not queue scan task: {exc}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable. Ensure Redis / Celery worker is running.",
        )

    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/project/{project_id}/history", response_model=List[ScanOut])
def scan_history(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _user_owns_project(project_id, current_user, db)
    return (
        db.query(Scan)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
