from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, ConfigDict

from app.models import SourceType, ScanStatus, Severity, TriageStatus


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(min_length=8)


class UserOut(UserBase):
    id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProjectBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class ProjectCreateGit(ProjectBase):
    source_type: SourceType = SourceType.git
    source_ref: str = Field(min_length=1)


class ProjectCreateUpload(ProjectBase):
    source_type: SourceType = SourceType.upload


class ProjectOut(ProjectBase):
    id: UUID
    owner_id: UUID
    source_type: SourceType
    source_ref: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanOut(BaseModel):
    id: UUID
    project_id: UUID
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    ruleset_version: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class FindingOut(BaseModel):
    id: UUID
    scan_id: UUID
    rule_id: str
    severity: Severity
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    code_snippet: Optional[str]
    description: str
    remediation: Optional[str]
    fingerprint: str
    status: TriageStatus
    triage_notes: Optional[str]
    triaged_by: Optional[UUID]
    triaged_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class TriageUpdate(BaseModel):
    status: TriageStatus
    notes: Optional[str] = None


class TriageEventOut(BaseModel):
    id: UUID
    finding_id: UUID
    actor_id: UUID
    previous_status: TriageStatus
    new_status: TriageStatus
    notes: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingFilter(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[TriageStatus] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class ReportRequest(BaseModel):
    include_all: bool = False


class DashboardSummary(BaseModel):
    total_projects: int
    total_findings: int
    findings_by_severity: dict
    last_scan_at: Optional[datetime]
