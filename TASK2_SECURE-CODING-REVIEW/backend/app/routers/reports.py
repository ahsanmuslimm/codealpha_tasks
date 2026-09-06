import os
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from jinja2 import Template
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Finding, Project, Scan, TriageStatus, User
from app.schemas import ReportRequest

router = APIRouter(prefix="/api/reports", tags=["reports"])

REPORT_TEMPLATE = """# CodeSentry Audit Report

**Project:** {{ project.name }}
**Scan ID:** {{ scan.id }}
**Ruleset:** {{ scan.ruleset_version or "unknown" }}
**Generated:** {{ generated_at }}
**Report scope:** {{ "All findings" if include_all else "Confirmed findings only" }}

---

## Executive Summary

| Metric | Value |
|---|---|
| Total findings in report | {{ findings|length }} |
| Critical | {{ severity_counts.critical }} |
| High | {{ severity_counts.high }} |
| Medium | {{ severity_counts.medium }} |
| Low | {{ severity_counts.low }} |
| Info | {{ severity_counts.info }} |

## Methodology

This audit was performed with CodeSentry, a static-analysis platform combining:

- **Semgrep** (SAST) using an OWASP Top 10 / CWE Top 25 curated ruleset.
- **OSV-Scanner** (SCA) for vulnerable dependencies.
- Manual triage to confirm, downgrade, or dismiss automated findings.

## Findings

{% for f in findings %}
### {{ loop.index }}. {{ f.rule_id }} — {{ f.severity.value.upper() }}

- **File:** `{{ f.file_path }}`{% if f.line_start %}:{{ f.line_start }}{% endif %}
- **CWE:** {{ f.cwe_id or "N/A" }}
- **OWASP Top 10 2021:** {{ f.owasp_category or "N/A" }}
- **Triage status:** {{ f.status.value }}
- **Triage notes:** {{ f.triage_notes or "None" }}

**Description:**
{{ f.description }}

**Evidence:**
```
{{ f.code_snippet or "N/A" }}
```

**Remediation:**
{{ f.remediation or "Investigate manually." }}

---

{% else %}
No findings matched the selected report scope.
{% endfor %}
"""


def _authorize_scan(scan_id: str, user: User, db: Session) -> Scan:
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.owner_id == user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("/scan/{scan_id}/markdown")
def export_markdown(
    scan_id: str,
    payload: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _authorize_scan(scan_id, current_user, db)
    project = scan.project

    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if not payload.include_all:
        q = q.filter(Finding.status == TriageStatus.confirmed)
    findings = q.all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.severity.value] += 1

    template = Template(REPORT_TEMPLATE)
    md = template.render(
        project=project,
        scan=scan,
        findings=findings,
        severity_counts=severity_counts,
        include_all=payload.include_all,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return {"format": "markdown", "content": md}


@router.post("/scan/{scan_id}/pdf")
def export_pdf(
    scan_id: str,
    payload: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        from weasyprint import HTML
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"PDF generation unavailable: {exc}",
        )

    md_response = export_markdown(scan_id, payload, db, current_user)
    import markdown as md_lib
    html = md_lib.markdown(md_response["content"])

    pdf_path = f"/tmp/report-{scan_id}.pdf"
    try:
        HTML(string=html).write_pdf(pdf_path)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"codesentry-report-{scan_id}.pdf",
            background=_cleanup_after_send(pdf_path),
        )
    except Exception as exc:
        # Clean up the temp file if response construction fails.
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {exc}",
        )


def _cleanup_after_send(path: str):
    """Return a BackgroundTask that deletes the temp file after the response is sent."""
    from starlette.background import BackgroundTask
    return BackgroundTask(lambda: os.path.exists(path) and os.remove(path))
