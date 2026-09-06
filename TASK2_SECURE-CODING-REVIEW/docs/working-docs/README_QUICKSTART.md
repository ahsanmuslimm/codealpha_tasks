# CodeSentry Quick Start Guide

A multi-language SAST + SCA platform for secure code review.

## Prerequisites

- Docker & Docker Compose (recommended) OR
- Python 3.11+, Node.js 20+, PostgreSQL 16, Redis 7
- Git (for cloning repos)

## Option 1: Run with Docker Compose (Easiest)

### 1. Clone and set up environment

```bash
cd backend
cp .env.example .env  # if provided, or create:
cat > .env << EOF
DATABASE_URL=postgresql://codesentry:codesentry@db:5432/codesentry
REDIS_URL=redis://redis:6379/0
SECRET_KEY=change-me-in-production
UPLOADS_DIR=/app/uploads
ARTIFACTS_DIR=/app/artifacts
USE_DOCKER_WORKER=true
CELERY_TASK_ALWAYS_EAGER=false
EOF
```

### 2. Build and start all services

```bash
cd ..  # back to project root
docker-compose up --build
```

This starts:
- **db** (PostgreSQL) on localhost:5432
- **redis** on localhost:6379
- **backend** (FastAPI) on localhost:8000
- **worker** (Celery) for async scans
- **frontend** (React) on localhost:3000

### 3. Access the platform

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs (Swagger UI)

### 4. Create account and run first scan

1. Go to http://localhost:3000
2. Sign up: `test@example.com` / `password123`
3. Click "+ New Project"
4. Choose "Git URL" and enter: `https://github.com/bkimminich/juice-shop.git`
5. Click "Create Project" → "Run Scan"
6. Wait 2–5 minutes for scan to complete (fetches ~100MB repo + runs Semgrep/OSV)
7. Click on the scan to view findings
8. Click on a finding to triage it

---

## Option 2: Local Development (No Docker Worker)

For faster iteration without Docker builder.

### 1. Install dependencies

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

**Frontend:**
```bash
cd frontend
npm install
```

### 2. Start PostgreSQL and Redis

```bash
# Docker only for services (not the full app)
docker run -d --name codesentry-db -e POSTGRES_PASSWORD=codesentry -p 5432:5432 postgres:16-alpine
docker run -d --name codesentry-redis -p 6379:6379 redis:7-alpine
```

### 3. Set environment variables

```bash
export DATABASE_URL=postgresql://codesentry:codesentry@localhost:5432/codesentry
export REDIS_URL=redis://localhost:6379/0
export SECRET_KEY=dev-secret
export USE_DOCKER_WORKER=false
export CELERY_TASK_ALWAYS_EAGER=true
export UPLOADS_DIR=./uploads
export ARTIFACTS_DIR=./artifacts
```

### 4. Create database

```bash
cd backend
python -c "from app.database import engine, Base; Base.metadata.create_all(bind=engine)"
```

### 5. Run backend + Celery worker (same process)

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. In another terminal, run frontend

```bash
cd frontend
npm run dev
```

This mode uses **fixture data** (pre-baked Semgrep/OSV outputs) instead of running the actual tools, so scans complete instantly. Perfect for UI development.

---

## Testing

### Run validation tests (no dependencies)

```bash
cd tests
python test_validation.py
# Output:
# PASS: private/link-local IPs blocked
# PASS: bad schemes blocked
# ... etc
```

### Run normalizer tests

```bash
python test_normalizer.py
# Output:
# sample-python: 5 normalized findings
# sample-js: 3 normalized findings
# sample-java: 2 normalized findings
```

### Run API integration tests (requires pytest)

```bash
pip install pytest pytest-asyncio
pytest tests/test_api_integration.py -v
```

### Run end-to-end tests

```bash
pytest tests/test_e2e_scan.py -v
```

---

## Workflow: Creating & Scanning a Project

### Via Web UI

1. **Login** → Sign up at http://localhost:3000/login
2. **New Project** → Choose source:
   - **Git URL:** `https://github.com/owner/repo.git`
   - **ZIP upload:** Select a .zip file (max 200 MB)
3. **Run Scan** → Status updates in real-time (queued → cloning → scanning_sast → scanning_sca → normalizing → complete)
4. **View Findings** → Table of issues sorted by severity
5. **Triage** → Click a finding, mark as Confirmed/False Positive/Won't Fix
6. **Export Report** → Download as Markdown or PDF (confirmed only)

### Via API (cURL)

**1. Sign up:**
```bash
curl -X POST http://localhost:8000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123"}'
```

**2. Log in:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -d "username=user@example.com&password=secure123"
# Returns: {"access_token":"...", "token_type":"bearer"}
```

**3. Create project:**
```bash
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
curl -X POST http://localhost:8000/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"My App",
    "source_type":"git",
    "source_ref":"https://github.com/example/repo.git"
  }'
# Returns: {"id":"...", "name":"My App", ...}
```

**4. Trigger scan:**
```bash
PROJECT_ID="550e8400-e29b-41d4-a716-446655440000"
curl -X POST http://localhost:8000/api/scans/project/$PROJECT_ID \
  -H "Authorization: Bearer $TOKEN"
# Returns: {"id":"...", "status":"queued", ...}
```

**5. Poll scan status:**
```bash
SCAN_ID="550e8400-e29b-41d4-a716-446655440001"
curl -X GET http://localhost:8000/api/scans/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN"
# Returns: {"id":"...", "status":"complete", ...}
```

**6. List findings:**
```bash
curl -X GET http://localhost:8000/api/findings/scan/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN"
# Returns: [{"id":"...", "severity":"critical", "cwe_id":"CWE-89", ...}, ...]
```

**7. Triage a finding:**
```bash
FINDING_ID="550e8400-e29b-41d4-a716-446655440002"
curl -X PATCH http://localhost:8000/api/findings/$FINDING_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status":"confirmed",
    "notes":"Verified real vulnerability. Assigned to team for fix."
  }'
```

**8. Export report:**
```bash
curl -X POST http://localhost:8000/api/reports/scan/$SCAN_ID/markdown \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"include_all":false}' > report.md
```

---

## Architecture

### Backend Stack

- **FastAPI** — async REST API
- **SQLAlchemy** — ORM for PostgreSQL
- **Alembic** — database migrations
- **Celery** — async task queue (with Redis broker)
- **Pydantic** — request/response validation
- **JWT** — stateless auth

### Frontend Stack

- **React 18** — UI framework
- **React Router** — client-side routing
- **Axios** — HTTP client
- **Vite** — build tool

### Security Stack

- **Semgrep** — SAST (static analysis)
- **OSV-Scanner** — SCA (dependency analysis)
- **Bcrypt** — password hashing
- **PyJWT** — JWT signing

---

## Configuration

### Backend Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis/Celery
REDIS_URL=redis://host:6379/0
CELERY_TASK_ALWAYS_EAGER=false  # Set true for testing without Redis

# Security
SECRET_KEY=your-random-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours

# Limits
MAX_UPLOAD_SIZE_BYTES=209715200  # 200 MB
MAX_ZIP_ENTRIES=10000
MAX_EXTRACTED_SIZE_BYTES=524288000  # 500 MB

# Scan
SCAN_TIMEOUT_SECONDS=600  # 10 minutes
SCAN_MEMORY_LIMIT=2g
SCAN_CPU_LIMIT=2.0
USE_DOCKER_WORKER=true

# Storage
UPLOADS_DIR=/app/uploads
ARTIFACTS_DIR=/app/artifacts
```

### Frontend Environment Variables

```env
VITE_API_URL=http://localhost:8000
```

---

## Troubleshooting

### "Scan queue unavailable"

**Problem:** Redis/Celery not running  
**Solution:** 
- Docker: Ensure `redis` service is up: `docker-compose ps`
- Local: Start Redis: `docker run -d -p 6379:6379 redis:7-alpine`
- Or: Set `CELERY_TASK_ALWAYS_EAGER=true` for synchronous testing

### "Database connection failed"

**Problem:** PostgreSQL not running or wrong connection string  
**Solution:**
- Docker: Check `db` service: `docker-compose logs db`
- Local: Verify `DATABASE_URL` is set and database exists
- Create database: `createdb -U codesentry codesentry`

### "Semgrep: command not found"

**Problem:** Semgrep not installed in Docker worker or local env  
**Solution:**
- Docker: Worker image should have Semgrep installed (see `worker/Dockerfile`)
- Local: Set `USE_DOCKER_WORKER=false` to use fixture data, or install: `pip install semgrep`

### Scan takes forever

**Problem:** Large repo or network timeout  
**Solution:**
- Increase `SCAN_TIMEOUT_SECONDS` in .env
- Use `--depth 1` for git clone (already done)
- For large repos, split into separate scans per microservice

### Frontend stuck on "Loading..."

**Problem:** Backend not responding  
**Solution:**
- Check backend: `curl http://localhost:8000/api/health`
- Check logs: `docker-compose logs backend`
- Check CORS: Backend should allow `http://localhost:3000`

---

## Production Deployment

### Recommended Setup

1. **Use managed PostgreSQL** (AWS RDS, Heroku Postgres, etc.)
2. **Use managed Redis** (AWS ElastiCache, Heroku Redis, etc.)
3. **Set `SECRET_KEY` to a strong random value**
4. **Disable debug mode:** `DEBUG=false`
5. **Use HTTPS** for all connections
6. **Implement rate limiting** on API (e.g., nginx)
7. **Monitor scans:** Alert if scan fails 3x in a row
8. **Backup database** daily
9. **Rotate logs** to prevent disk exhaustion
10. **Use secrets manager** (AWS Secrets Manager, HashiCorp Vault) for credentials

### Kubernetes Deployment (Optional)

See `k8s/` directory (if provided) for YAML manifests:
- Deployment for backend
- StatefulSet for worker (auto-scale via HPA)
- Service + Ingress
- PersistentVolume for artifacts

---

## License & Attribution

**CodeSentry** — Developed for CodeAlpha Internship, Cybersecurity Task 2 (2026)

**Third-party Tools:**
- [Semgrep](https://semgrep.dev/) — Static analysis (LGPL)
- [OSV-Scanner](https://github.com/google/osv-scanner) — Dependency scanning (Apache 2.0)
- [FastAPI](https://fastapi.tiangolo.com/) — Web framework (MIT)
- [React](https://react.dev/) — UI framework (MIT)

---

## Support & Contributing

For issues or questions:
1. Check this README and METHODOLOGY.md
2. Review logs: `docker-compose logs backend` or `uvicorn` terminal
3. Check API docs: http://localhost:8000/docs
4. Run tests: `pytest tests/ -v`

---

**Version:** 1.0.0  
**Last Updated:** September 2026
