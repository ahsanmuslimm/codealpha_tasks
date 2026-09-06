from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import get_settings
from app.database import engine, get_db
from app.models import Base, Finding, Project, Scan, Severity, User
from app.routers import auth, findings, projects, reports, scans
from app.schemas import DashboardSummary

settings = get_settings()

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app_name,
    description="Multi-language secure code review platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/dashboard", response_model=DashboardSummary)
def dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project_ids_subquery = (
        db.query(Project.id)
        .filter(Project.owner_id == current_user.id)
        .subquery()
    )

    total_projects = db.query(Project).filter(Project.owner_id == current_user.id).count()
    total_findings = (
        db.query(Finding)
        .join(Scan)
        .filter(Scan.project_id.in_(project_ids_subquery))
        .count()
    )

    severity_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .join(Scan)
        .filter(Scan.project_id.in_(project_ids_subquery))
        .group_by(Finding.severity)
        .all()
    )
    findings_by_severity = {s.value: 0 for s in Severity}
    for severity, count in severity_counts:
        findings_by_severity[severity.value] = count

    last_scan = (
        db.query(Scan)
        .join(Project)
        .filter(Project.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    return DashboardSummary(
        total_projects=total_projects,
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
        last_scan_at=last_scan.created_at if last_scan else None,
    )
