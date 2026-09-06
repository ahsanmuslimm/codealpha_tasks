# Technical Requirement Document (TRD)
## Product: CodeSentry

---

### 1. Architecture Overview

```
                          ┌─────────────────────┐
                          │   React Frontend     │
                          │  (Dashboard/Triage)  │
                          └──────────┬───────────┘
                                     │ REST/JSON (JWT auth)
                          ┌──────────▼───────────┐
                          │   FastAPI Backend     │
                          │  (API + Auth + Orch.) │
                          └───┬───────────────┬───┘
                              │               │
                   ┌──────────▼───┐   ┌───────▼────────┐
                   │  PostgreSQL   │   │  Redis + Celery │
                   │ (metadata,    │   │  (job queue)     │
                   │  findings)    │   └───────┬────────┘
                   └───────────────┘           │
                                     ┌──────────▼───────────┐
                                     │  Scan Worker(s)       │
                                     │  - clone repo (sandbox)│
                                     │  - run Semgrep         │
                                     │  - run OSV-Scanner     │
                                     │  - normalize findings  │
                                     │  runs INSIDE isolated  │
                                     │  Docker container       │
                                     │  (no network egress,    │
                                     │  read-only mounts,       │
                                     │  resource limits)        │
                                     └──────────────────────────┘
```

### 2. Why This Stack (justified, not default)

- **Semgrep as core SAST engine**: single rule syntax across 30+ languages, actively maintained OWASP/CWE-mapped rule packs, avoids reinventing static analysis. This is the technical fact that makes "multi-language" true rather than aspirational.
- **OSV-Scanner for SCA**: covers the class of vulnerabilities pure SAST misses entirely — vulnerable dependencies (e.g., Log4Shell-class issues) — without which "comprehensive" review is incomplete.
- **FastAPI**: async-native (needed for job polling/streaming scan status), Python-native (same runtime family as Semgrep tooling, minimizes subprocess friction), automatic OpenAPI docs (useful for the internship documentation deliverable).
- **Celery + Redis**: scans are long-running (seconds to minutes depending on repo size) — must be async job-queued, never a blocking HTTP request. A synchronous scan endpoint is itself a DoS vector (see Threat Model §5).
- **Docker-per-scan-job isolation**: mandatory, not optional. The tool's core function is executing static analysis over **untrusted third-party source code**. Without sandboxing, a malicious target repo (e.g., a build script triggered by an IDE-integration-style hook, or a zip-bomb) becomes a compromise of the scanning host itself.

### 3. Threat Model (the tool auditing itself — required, not optional)

| # | Threat | Vector | Mitigation |
|---|---|---|---|
| T1 | Zip-bomb / decompression DoS on upload | Malicious archive with high compression ratio | Enforce max extracted size + file count before decompression completes; stream-limit decompression |
| T2 | Path traversal on archive extraction | `../../etc/passwd`-style entries in zip | Sanitize/reject any entry path escaping extraction root |
| T3 | Resource exhaustion via oversized/malicious repo | Huge repo, infinite symlink loops, huge single file | Per-scan CPU/memory/time limits (Docker `--memory`, `--cpus`, timeout kill) |
| T4 | Arbitrary code execution during scan | Malicious pre-commit hooks, build scripts, `package.json` install scripts | Static analysis only — never run `npm install`, `pip install`, or execute target code. Semgrep/OSV operate on source text/manifests, not by executing the target |
| T5 | SSRF via git clone URL | User supplies internal URL (`http://169.254.169.254/...`) as "repo to scan" | Allowlist git/https schemes only, block private/link-local IP ranges before clone |
| T6 | IDOR on findings/reports | User A requests scan/report ID belonging to User B | Every query scoped by `owner_id`/`project_id` + auth check, never trust client-supplied IDs alone |
| T7 | Stored XSS via rendered code snippets in frontend | Malicious source code containing `<script>` rendered unescaped in finding detail view | Escape/sandbox all code-snippet rendering (never `dangerouslySetInnerHTML` raw); use a code viewer component that treats content as text, not HTML |
| T8 | Secrets leakage in reports | Repo contains hardcoded secrets, tool includes raw snippet in exported report shared insecurely | Add secret-detection pass (e.g., regex/entropy check via Semgrep secrets ruleset) and redact matched values in report by default |

### 4. Non-Functional Requirements

- Scan timeout: hard-kill at 10 minutes per job
- Max upload size: 200MB (configurable)
- All scan workers run as non-root container user
- No outbound network access from scan container except the initial git clone step (then network disabled for the analysis phase)
- Audit log: every triage decision (who, what, when) immutable/append-only

### 5. API Surface (high-level)

```
POST   /api/projects                 create project (repo URL or upload)
POST   /api/projects/{id}/scans      trigger scan (async, returns job_id)
GET    /api/scans/{id}               scan status/progress
GET    /api/scans/{id}/findings      list findings (paginated, filterable by severity/CWE)
PATCH  /api/findings/{id}            triage update (status, notes)
GET    /api/scans/{id}/report        generate/export report (pdf/md)
POST   /api/auth/login               JWT auth
```

### 6. Language Coverage Statement (technical honesty)

Semgrep officially supports high-confidence rule packs for: JavaScript/TypeScript, Python, Java, Go, Ruby, PHP, C#, and generic pattern matching for others. **This project will explicitly validate and demo against JS/TS, Python, and Java** (chosen for real-world audit relevance), while the architecture is language-agnostic beyond that set — this is the accurate claim, not "all languages."
