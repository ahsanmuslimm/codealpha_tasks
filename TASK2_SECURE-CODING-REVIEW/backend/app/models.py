import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, String, Integer, DateTime, Text, Enum, Index
from sqlalchemy.orm import relationship

from app.database import Base


def now_utc():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class SourceType(str, enum.Enum):
    git = "git"
    upload = "upload"


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    source_type = Column(Enum(SourceType), nullable=False)
    source_ref = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)

    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class ScanStatus(str, enum.Enum):
    queued = "queued"
    cloning = "cloning"
    scanning_sast = "scanning_sast"
    scanning_sca = "scanning_sca"
    normalizing = "normalizing"
    complete = "complete"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.queued, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    ruleset_version = Column(String, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    artifacts = relationship("ScanArtifact", back_populates="scan", cascade="all, delete-orphan")


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class TriageStatus(str, enum.Enum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    wont_fix = "wont_fix"
    needs_review = "needs_review"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    rule_id = Column(String, ForeignKey("rules.id"), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    cwe_id = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)
    file_path = Column(Text, nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    fingerprint = Column(String, nullable=False, index=True)
    status = Column(Enum(TriageStatus), default=TriageStatus.open, nullable=False)
    triage_notes = Column(Text, nullable=True)
    triaged_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    triaged_at = Column(DateTime(timezone=True), nullable=True)

    scan = relationship("Scan", back_populates="findings")
    rule = relationship("Rule", back_populates="findings")
    triage_events = relationship("TriageEvent", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )


class TriageEvent(Base):
    __tablename__ = "triage_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    actor_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    previous_status = Column(Enum(TriageStatus), nullable=False)
    new_status = Column(Enum(TriageStatus), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)

    finding = relationship("Finding", back_populates="triage_events")


class RuleSource(str, enum.Enum):
    semgrep = "semgrep"
    osv = "osv"


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True)
    source = Column(Enum(RuleSource), nullable=False)
    description = Column(Text, nullable=False)
    default_severity = Column(Enum(Severity), nullable=False)
    cwe_id = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)

    findings = relationship("Finding", back_populates="rule")


class ArtifactType(str, enum.Enum):
    raw_semgrep_json = "raw_semgrep_json"
    raw_osv_json = "raw_osv_json"


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    type = Column(Enum(ArtifactType), nullable=False)
    storage_path = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="artifacts")
