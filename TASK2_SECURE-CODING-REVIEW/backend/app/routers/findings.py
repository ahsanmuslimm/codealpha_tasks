from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Finding, Project, Scan, Severity, TriageEvent, TriageStatus, User
from app.schemas import FindingFilter, FindingOut, TriageEventOut, TriageUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _authorize_finding(finding_id: str, user: User, db: Session) -> Finding:
    finding = (
        db.query(Finding)
        .join(Scan)
        .join(Project)
        .filter(Finding.id == finding_id, Project.owner_id == user.id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.get("/scan/{scan_id}", response_model=List[FindingOut])
def list_findings(
    scan_id: str,
    severity: Optional[Severity] = None,
    status: Optional[TriageStatus] = None,
    cwe_id: Optional[str] = None,
    owasp_category: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
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

    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if cwe_id:
        q = q.filter(Finding.cwe_id == cwe_id)
    if owasp_category:
        q = q.filter(Finding.owasp_category == owasp_category)

    # Sort Critical → High → Medium → Low → Info using an explicit case expression.
    severity_order = case(
        (Finding.severity == Severity.critical, 0),
        (Finding.severity == Severity.high, 1),
        (Finding.severity == Severity.medium, 2),
        (Finding.severity == Severity.low, 3),
        (Finding.severity == Severity.info, 4),
        else_=5,
    )

    return (
        q.order_by(severity_order)
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.patch("/{finding_id}", response_model=FindingOut)
def triage_finding(
    finding_id: str,
    payload: TriageUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = _authorize_finding(finding_id, current_user, db)
    previous = finding.status

    finding.status = payload.status
    finding.triage_notes = payload.notes
    finding.triaged_by = current_user.id
    finding.triaged_at = datetime.now(timezone.utc)

    event = TriageEvent(
        finding_id=finding.id,
        actor_id=current_user.id,
        previous_status=previous,
        new_status=payload.status,
        notes=payload.notes,
    )
    db.add(event)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/{finding_id}/history", response_model=List[TriageEventOut])
def finding_history(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _authorize_finding(finding_id, current_user, db)
    return (
        db.query(TriageEvent)
        .filter(TriageEvent.finding_id == finding_id)
        .order_by(TriageEvent.created_at.desc())
        .all()
    )
