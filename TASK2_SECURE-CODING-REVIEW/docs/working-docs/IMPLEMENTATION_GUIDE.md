# CodeSentry Implementation Guide

Complete technical documentation for deploying, extending, and maintaining CodeSentry.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Database Schema](#database-schema)
3. [API Reference](#api-reference)
4. [Deployment](#deployment)
5. [Extending CodeSentry](#extending-codesentry)
6. [Monitoring & Maintenance](#monitoring--maintenance)
7. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Users/Auditors                           │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────────────────┐
│                    Frontend (React)                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Components: Dashboard, NewProject, ProjectDetail,   │   │
│  │ ScanDetail, FindingDetail, Reports                  │   │
│  └────────────────────┬────────────────────────────────┘   │
└─────────────────────────┬────────────────────────────────────┘
                          │ REST API
┌─────────────────────────▼────────────────────────────────────┐
│                  Backend (FastAPI)                          │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Routers: auth, projects, scans, findings, reports │    │
│  └────────────────────────────────────────────────────┘    │
│                       ↓                                      │
│  ┌──────────────────┐  ┌──────────────────────┐            │
│  │   PostgreSQL DB  │  │  Redis Queue (Celery)│            │
│  │                  │  │  - Job storage       │            │
│  │ Tables:          │  │  - Task state        │            │
│  │ - users          │  │  - Rate limiting     │            │
│  │ - projects       │  └──────────────────────┘            │
│  │ - scans          │                                       │
│  │ - findings       │                                       │
│  │ - rules          │     ┌──────────────────┐             │
│  │ - triage_events  │────▶│  Celery Worker   │             │
│  │ - artifacts      │     │  (Async Tasks)   │             │
│  └──────────────────┘     └────────┬─────────┘             │
│                                    │                        │
└────────────────────────────────────┼────────────────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
         ┌───────▼────────┐  ┌──────▼────────┐  ┌──────▼──────┐
         │  Direct Scan   │  │ Docker Worker │  │ Fixtures    │
         │   (dev/test)   │  │  (production) │  │  (fallback) │
         │                │  │               │  │             │
         │ • Semgrep      │  │ • Semgrep     │  │ • Pre-baked │
         │ • OSV-Scanner  │  │ • OSV-Scanner │  │   results   │
         │ • Git clone    │  │ • Isolated    │  │             │
         │ • ZIP extract  │  │ • Bounded res │  │             │
         └────────────────┘  └───────────────┘  └─────────────┘
```

### Data Flow

```
1. User Flow:
   User Signup/Login → JWT Token → Create Project → Trigger Scan

2. Scan Flow:
   Trigger Scan → Celery Task Queued → Scan Status Updated
   → Clone/Extract Source → Run Semgrep → Run OSV → Normalize Findings
   → Persist to DB → Scan Status Complete

3. Triage Flow:
   View Findings → Filter/Sort → Select Finding → Update Status
   → Create TriageEvent (audit log) → Export Report

4. Report Flow:
   Generate Report (filter by status) → Render Template
   → Convert to PDF (optional) → Download
```

---

## Database Schema

### Users Table

```sql
CREATE TABLE users (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ix_users_email ON users(email);
```

**Model:**
```python
class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
```

### Projects Table

```sql
CREATE TABLE projects (
  id VARCHAR(36) PRIMARY KEY,
  owner_id VARCHAR(36) NOT NULL REFERENCES users(id),
  name VARCHAR(255) NOT NULL,
  source_type VARCHAR(10) NOT NULL,  -- 'git' or 'upload'
  source_ref TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ix_projects_owner_id ON projects(owner_id);
```

**Model:**
```python
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
```

### Scans Table

```sql
CREATE TABLE scans (
  id VARCHAR(36) PRIMARY KEY,
  project_id VARCHAR(36) NOT NULL REFERENCES projects(id),
  status VARCHAR(20) NOT NULL,  -- queued, cloning, scanning_sast, ...
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  error_message TEXT,
  ruleset_version VARCHAR(50)
);

CREATE INDEX ix_scans_project_id ON scans(project_id);
```

**Status Transitions:**
```
queued → cloning → scanning_sast → scanning_sca → normalizing → complete
                                                              ↓
                                                             failed (at any step)
```

### Rules Table (Catalog)

```sql
CREATE TABLE rules (
  id VARCHAR(255) PRIMARY KEY,
  source VARCHAR(20) NOT NULL,  -- 'semgrep' or 'osv'
  description TEXT NOT NULL,
  default_severity VARCHAR(20) NOT NULL,
  cwe_id VARCHAR(10),
  owasp_category VARCHAR(50)
);

-- Examples:
INSERT INTO rules VALUES (
  'semgrep:python.django.security.injection.sql-injection',
  'semgrep',
  'Unvalidated SQL query',
  'high',
  'CWE-89',
  'A03:2021-Injection'
);

INSERT INTO rules VALUES (
  'osv:lodash:CVE-2021-23337',
  'osv',
  'Prototype pollution in lodash',
  'high',
  'CWE-1321',
  'A06:2021-Vulnerable and Outdated Components'
);
```

### Findings Table (Core)

```sql
CREATE TABLE findings (
  id VARCHAR(36) PRIMARY KEY,
  scan_id VARCHAR(36) NOT NULL REFERENCES scans(id),
  rule_id VARCHAR(255) NOT NULL REFERENCES rules(id),
  severity VARCHAR(20) NOT NULL,  -- critical, high, medium, low, info
  cwe_id VARCHAR(10),
  owasp_category VARCHAR(50),
  file_path TEXT NOT NULL,
  line_start INTEGER,
  line_end INTEGER,
  code_snippet TEXT,  -- Max 4000 chars, redacted for secrets
  description TEXT NOT NULL,
  remediation TEXT,
  fingerprint VARCHAR(64) NOT NULL UNIQUE INDEX,  -- SHA256(rule_id|file|snippet)
  status VARCHAR(20) NOT NULL DEFAULT 'open',  -- open, confirmed, false_positive, ...
  triage_notes TEXT,
  triaged_by VARCHAR(36) REFERENCES users(id),
  triaged_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX ix_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX ix_findings_fingerprint ON findings(fingerprint);
```

### TriageEvents Table (Audit Log)

```sql
CREATE TABLE triage_events (
  id VARCHAR(36) PRIMARY KEY,
  finding_id VARCHAR(36) NOT NULL REFERENCES findings(id),
  actor_id VARCHAR(36) NOT NULL REFERENCES users(id),
  previous_status VARCHAR(20) NOT NULL,
  new_status VARCHAR(20) NOT NULL,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ix_triage_events_finding_id ON triage_events(finding_id);
```

**Example Entry:**
```sql
INSERT INTO triage_events (id, finding_id, actor_id, previous_status, new_status, notes, created_at)
VALUES (
  'abc123',
  'finding-456',
  'user-789',
  'open',
  'confirmed',
  'Verified real vulnerability. SQL injection confirmed via manual testing.',
  '2026-09-10T15:30:00Z'
);
```

### ScanArtifacts Table

```sql
CREATE TABLE scan_artifacts (
  id VARCHAR(36) PRIMARY KEY,
  scan_id VARCHAR(36) NOT NULL REFERENCES scans(id),
  type VARCHAR(50) NOT NULL,  -- 'raw_semgrep_json', 'raw_osv_json'
  storage_path TEXT NOT NULL
);

CREATE INDEX ix_scan_artifacts_scan_id ON scan_artifacts(scan_id);
```

---

## API Reference

### Authentication

#### POST /api/auth/signup

Create a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure123"
}
```

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "created_at": "2026-09-10T10:00:00Z"
}
```

**Errors:**
- `409 Conflict`: Email already registered
- `422 Unprocessable Entity`: Password too short (<8 chars)

---

#### POST /api/auth/login

Authenticate and receive JWT token.

**Request:**
```
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=secure123
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Usage:**
```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

### Projects

#### POST /api/projects

Create a project from git URL.

**Request:**
```json
{
  "name": "My App",
  "source_type": "git",
  "source_ref": "https://github.com/owner/repo.git"
}
```

**Validation:**
- `name`: 1–255 characters
- `source_ref`: Valid HTTPS/SSH git URL, not private IP

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "owner_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My App",
  "source_type": "git",
  "source_ref": "https://github.com/owner/repo.git",
  "created_at": "2026-09-10T10:05:00Z"
}
```

---

#### POST /api/projects/upload

Create a project from ZIP file upload.

**Request:**
```
Content-Type: multipart/form-data

name=My App&file=@/path/to/project.zip
```

**Validation:**
- Max file size: 200 MB
- Max ZIP entries: 10,000
- Max extracted size: 500 MB
- Must be valid ZIP archive

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "name": "My App",
  "source_type": "upload",
  "source_ref": "/app/uploads/project-id/...",
  "created_at": "2026-09-10T10:05:00Z"
}
```

---

#### GET /api/projects

List all projects owned by current user.

**Response (200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "owner_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "My App",
    "source_type": "git",
    "source_ref": "https://github.com/owner/repo.git",
    "created_at": "2026-09-10T10:05:00Z"
  }
]
```

---

### Scans

#### POST /api/scans/project/{project_id}

Trigger a new scan for a project.

**Request:**
```
POST /api/scans/project/550e8400-e29b-41d4-a716-446655440001
```

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440010",
  "project_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "queued",
  "created_at": "2026-09-10T10:10:00Z",
  "started_at": null,
  "completed_at": null,
  "error_message": null,
  "ruleset_version": "codesentry-v1.0"
}
```

**Side Effects:**
- Celery task enqueued
- Scan record persisted with status=queued
- Starts transitions: queued → cloning → scanning_sast → ...

---

#### GET /api/scans/{scan_id}

Get scan details.

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440010",
  "project_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "complete",
  "created_at": "2026-09-10T10:10:00Z",
  "started_at": "2026-09-10T10:11:00Z",
  "completed_at": "2026-09-10T10:14:30Z",
  "error_message": null,
  "ruleset_version": "codesentry-v1.0"
}
```

---

### Findings

#### GET /api/findings/scan/{scan_id}

List findings from a scan.

**Query Parameters:**
- `severity` (optional): critical, high, medium, low, info
- `triage_status` (optional): open, confirmed, false_positive, won't_fix, needs_review
- `cwe_id` (optional): CWE-89, CWE-79, etc.
- `owasp_category` (optional): A03:2021-Injection, etc.
- `skip` (optional, default=0): Pagination offset
- `limit` (optional, default=50, max=200): Pagination limit

**Request:**
```
GET /api/findings/scan/550e8400-e29b-41d4-a716-446655440010?severity=critical&skip=0&limit=50
```

**Response (200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440020",
    "scan_id": "550e8400-e29b-41d4-a716-446655440010",
    "rule_id": "semgrep:python.django.security.injection.sql-injection",
    "severity": "critical",
    "cwe_id": "CWE-89",
    "owasp_category": "A03:2021-Injection",
    "file_path": "app/views.py",
    "line_start": 42,
    "line_end": 42,
    "code_snippet": "db.query(f'SELECT * FROM users WHERE id={user_id}')",
    "description": "SQL injection via f-string",
    "remediation": "Use parameterized query",
    "fingerprint": "abc123...",
    "status": "open",
    "triage_notes": null,
    "triaged_by": null,
    "triaged_at": null
  }
]
```

---

#### PATCH /api/findings/{finding_id}

Update triage status of a finding.

**Request:**
```json
{
  "status": "confirmed",
  "notes": "Verified real vulnerability. SQL injection confirmed."
}
```

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440020",
  "status": "confirmed",
  "triage_notes": "Verified real vulnerability. SQL injection confirmed.",
  "triaged_by": "550e8400-e29b-41d4-a716-446655440000",
  "triaged_at": "2026-09-10T15:30:00Z",
  "...": "..."
}
```

**Side Effects:**
- TriageEvent record created (audit log)
- Fingerprint indexed for carry-forward to future scans

---

### Reports

#### POST /api/reports/scan/{scan_id}/markdown

Generate Markdown report.

**Request:**
```json
{
  "include_all": false
}
```

**Response (200):**
```json
{
  "format": "markdown",
  "content": "# CodeSentry Audit Report\n\n**Project:** ...\n\n## Executive Summary\n\n..."
}
```

**Filtering:**
- `include_all: true` — all statuses
- `include_all: false` — confirmed only

---

#### POST /api/reports/scan/{scan_id}/pdf

Generate PDF report.

**Request:**
```json
{
  "include_all": false
}
```

**Response (200):**
- Content-Type: `application/pdf`
- Binary PDF content

---

## Deployment

### Docker Compose (Development)

```yaml
version: "3.9"

services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: codesentry
      POSTGRES_PASSWORD: codesentry
      POSTGRES_DB: codesentry
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U codesentry"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://codesentry:codesentry@db:5432/codesentry
      REDIS_URL: redis://redis:6379/0
      SECRET_KEY: ${SECRET_KEY:-dev-secret}
      USE_DOCKER_WORKER: "true"
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  worker:
    build: ./worker
    environment:
      SCAN_ID: ""
    volumes:
      - scan_work:/workspace/out

  frontend:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./frontend:/app
    ports:
      - "3000:3000"
    environment:
      VITE_API_URL: http://localhost:8000
    command: sh -c "npm install && npm run dev"

volumes:
  postgres_data:
  scan_work:
```

**Start:**
```bash
docker-compose up --build
```

### Kubernetes (Production)

**Deployment manifest (optional):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: codesentry-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: codesentry-backend
  template:
    metadata:
      labels:
        app: codesentry-backend
    spec:
      containers:
      - name: backend
        image: codesentry-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: codesentry-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: codesentry-secrets
              key: redis-url
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "500m"
            memory: "256Mi"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
```

---

## Extending CodeSentry

### Adding a Custom Rule

**Create custom Semgrep rule:**

```yaml
# custom-rules.yaml
rules:
  - id: custom.django.csrf-bypass
    pattern: |
      @csrf_exempt
      def $FUNC(...):
        ...
    message: "CSRF protection disabled with @csrf_exempt"
    severity: WARNING
    metadata:
      cwe: "CWE-352"
      owasp: "A01:2021"
```

**Use in scan:**
```python
# In tasks.py, run_direct_scan():
rules = "p/owasp-top-ten,p/cwe-top-25,./custom-rules.yaml"
subprocess.run(["semgrep", "--config", rules, ...])
```

### Adding a New Language Support

1. Add language-specific manifest file patterns to `_run_direct_scan()`
2. Add OSV-Scanner support (usually automatic)
3. Add Semgrep language pack: `p/python`, `p/java`, etc.
4. Test with sample app in that language

### Integrating with CI/CD

**GitHub Actions example:**

```yaml
name: CodeSentry Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run CodeSentry
        run: |
          docker run -v ${{ github.workspace }}:/workspace \
            codesentry-worker
      - name: Upload findings
        if: always()
        run: |
          curl -X POST http://codesentry-api/import-scan \
            -H "Authorization: Bearer ${{ secrets.CODESENTRY_TOKEN }}" \
            -d @semgrep.json
```

---

## Monitoring & Maintenance

### Health Checks

```bash
# API health
curl http://localhost:8000/api/health

# Database
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"

# Redis
redis-cli PING

# Celery
celery -A app.tasks inspect active
```

### Metrics to Monitor

- **Scan success rate:** (completed / total) × 100
- **Average scan duration:** mean(completed_at - started_at)
- **False positive rate:** (false_positive / confirmed) × 100
- **Findings per scan:** total / num_scans
- **API response time:** p50, p95, p99 latencies
- **Database size:** GB per month growth
- **Celery queue depth:** pending tasks

### Log Locations

- **Backend:** `docker-compose logs backend`
- **Worker:** `docker-compose logs worker`
- **Database:** `docker-compose logs db`
- **Frontend:** Browser DevTools console

### Backup & Recovery

**Database backup:**
```bash
pg_dump postgresql://codesentry:codesentry@localhost/codesentry > backup.sql
```

**Restore:**
```bash
psql postgresql://codesentry:codesentry@localhost/codesentry < backup.sql
```

**Artifacts backup:**
```bash
tar -czf artifacts.tar.gz /app/artifacts/
```

---

## Troubleshooting

### Scan stuck in "cloning" state

**Symptoms:** Scan status never progresses from "cloning"

**Causes:**
1. Git URL is incorrect or unreachable
2. Network timeout (repo too large)
3. Worker not running

**Fix:**
```bash
# Check worker logs
docker-compose logs worker

# Manually verify git URL
git clone --depth 1 https://github.com/example/repo.git /tmp/test

# Increase timeout in .env
SCAN_TIMEOUT_SECONDS=1200
```

### "ModuleNotFoundError: No module named 'app'"

**Fix:**
```bash
# Ensure backend/requirements.txt is installed
pip install -r backend/requirements.txt

# Check PYTHONPATH
export PYTHONPATH=/app/backend:$PYTHONPATH
```

### PostgreSQL connection refused

**Symptoms:** `psycopg2.OperationalError: could not connect to server`

**Fix:**
```bash
# Check database URL
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1"

# Start PostgreSQL if using Docker
docker-compose up -d db
```

### OutOfMemory during large scan

**Symptoms:** Scan worker crashes, no error message

**Fix:**
```bash
# Increase Docker memory limit
# In docker-compose.yml:
services:
  worker:
    deploy:
      resources:
        limits:
          memory: 4G

# Or split large repo:
# Run scans per language or module separately
```

---

**End of Implementation Guide**
