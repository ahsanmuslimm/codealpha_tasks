# CodeSentry — Multi-Language Secure Code Review Platform

CodeSentry ingests source code (git URL or ZIP upload), runs Semgrep (SAST) and OSV-Scanner (SCA) inside an isolated Docker worker, normalizes findings into a unified model, supports manual triage with an immutable audit log, and exports defensible Markdown/PDF audit reports.

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.11+ and Node 20+ for local development

### Build and run

```bash
# Build the worker image first
docker build -t codesentry-worker ./worker

# Start the platform
docker-compose up --build
```

Services:

- Backend API: http://localhost:8000
- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

### First-time setup

1. Open the frontend at http://localhost:3000
2. Sign up, then log in
3. Create a project (git URL or ZIP upload)
4. Click **Run Scan**
5. Wait for the scan to complete, then triage findings and export a report

## Architecture

```
React Frontend  ──REST/JWT──►  FastAPI Backend
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       │                            │                            │
  PostgreSQL                   Redis + Celery              Docker Worker
  (metadata, findings)         (job queue)                 Semgrep + OSV-Scanner
```

## Security Controls

| ID | Threat | Mitigation |
|---|---|---|
| T1 | Zip-bomb DoS | Max upload size, max entries, max extracted size enforced before extraction |
| T2 | Path traversal | Zip entry paths sanitized and resolved inside extraction root |
| T3 | Resource exhaustion | Docker `--memory`, `--cpus`, and hard timeout per scan job |
| T4 | Arbitrary code execution | Static analysis only; worker never installs dependencies or executes target code |
| T5 | SSRF via git URL | Scheme allowlist + block private/link-local/loopback IPs |
| T6 | IDOR | All queries scoped by authenticated `owner_id` |
| T7 | Stored XSS | Code snippets rendered as text (no raw HTML injection) |
| T8 | Secrets leakage | Secret-detection rules run with critical severity; snippet redacted |

## Project Structure

```
.
├── backend/          FastAPI app, models, API routes, Celery tasks
├── worker/           Dockerized Semgrep + OSV-Scanner scan worker
├── frontend/         React dashboard and triage UI
├── docs/             PRD, TRD, schema, implementation plan
└── docker-compose.yml
```

## Development Notes

- Backend tests its own security validators in `backend/app/services/validation.py`.
- Run the Celery worker locally with: `celery -A app.tasks worker --loglevel=info`
- Run the frontend locally with: `cd frontend && npm install && npm run dev`

## Internship Deliverable

The tool source code plus audit reports for at least three real/sample applications across three languages. See `docs/06_Implementation_Plan_CodeSentry.md` for the full roadmap.
