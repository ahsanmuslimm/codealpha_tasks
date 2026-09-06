# CodeSentry — Secure Coding Review Platform Plan

## 1. What We Are Building

- **Product:** CodeSentry, a multi-language SAST + SCA code-review platform.
- **Core purpose:** Ingest a repo (git URL or ZIP), run Semgrep (SAST) and OSV-Scanner (SCA) inside an isolated Docker worker, normalize findings into a unified model, let a human triage them, and export a defensible audit report.
- **Why this design:** It satisfies the literal internship task ("perform a secure coding review") by automating the repeatable parts while preserving the required human judgment layer (triage, exploitability reasoning, remediation guidance).

## 2. Deliverables & Success Criteria

- Working tool source code and architecture docs.
- Tool scans ≥3 real/sample applications across ≥3 languages without crashing.
- ≥90% of findings are manually triaged (not raw scanner output).
- Each confirmed finding maps to CWE + OWASP Top 10 2021 with actionable remediation.
- At least one confirmed finding per target app includes real exploitability reasoning.

## 3. Tech Stack

- **Frontend:** React (dark-mode security dashboard, findings list, triage slide-over, report export preview).
- **Backend:** FastAPI (async API + auth + orchestration), PostgreSQL (metadata/findings), Redis + Celery (async scan jobs).
- **Scan engine:** Semgrep (curated OWASP/CWE ruleset) + OSV-Scanner (dependency CVEs).
- **Sandbox:** Docker per-scan-job, non-root user, resource limits, no outbound network after clone.

## 4. Build Phases

### Phase 1 — Backend Core (Days 1–3)
- FastAPI project scaffold, Alembic migrations for PostgreSQL schema from Doc 5.
- JWT auth, users/projects CRUD.
- Git URL validation: allowlist `https`/`git` schemes, block private/link-local IPs (SSRF mitigation T5).
- ZIP upload endpoint: max size, entry count, path-traversal sanitization (T1/T2).
- Celery + Redis job queue wired to scan trigger endpoint.
- Exit: project creation + scan job reaches `queued` reliably.

### Phase 2 — Scan Engine (Days 4–6)
- Docker worker image with Semgrep + OSV-Scanner, non-root user, `--memory`, `--cpus`, timeout.
- Worker clones repo or extracts zip inside container, then disables network for analysis.
- Run Semgrep with curated ruleset (OWASP Top 10 + CWE Top 25 subset), not all rules.
- Run OSV-Scanner on detected manifests (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`).
- Normalize outputs to unified `findings` schema: severity, CWE ID, OWASP category, file/line, snippet, remediation.
- Persist raw output as `scan_artifacts` for reproducibility.
- Exit: known-vulnerable sample repo produces populated, correctly-classified findings.

### Phase 3 — Triage + Reports (Days 7–9)
- Findings list API with filters (severity, CWE, status) and pagination.
- Triage PATCH endpoint + append-only `triage_events` audit log.
- Fingerprint-based carry-forward of triage decisions on re-scans.
- Report generation: Markdown + PDF export, default "Confirmed only".
- Exit: feature freeze — backend fully functional via API/Postman.

### Phase 4 — Frontend (Days 10–12)
- Login → Dashboard → New Project → Project Detail → Scan Detail → Finding Detail → Export Report.
- Severity-coded findings table, text-only code viewer (T7 stored-XSS mitigation), triage controls, audit trail.
- Poll-based scan status UI.
- Exit: full end-to-end walkthrough in browser.

### Phase 5 — Real Audits (Days 13–14+)
- Run CodeSentry against ≥3 real apps across ≥3 languages.
- Recommended targets: OWASP Juice Shop (JS/TS), a Python Flask/Django sample with known CVEs, a Java Spring sample or small open-source repo.
- Manually triage every Critical/High finding; document exploitability and business impact.
- Export final audit report per target.
- Write "Methodology & Tool Design" cover document.

## 5. Security Controls (Threat Model T1–T8)

| Threat | Mitigation | Validation |
|---|---|---|
| T1 Zip-bomb DoS | Max extracted size + file count before full extraction | Unit test with oversized zip |
| T2 Path traversal | Reject archive entries escaping extraction root | Unit test with `../../` filename |
| T3 Resource exhaustion | Docker `--memory`, `--cpus`, hard timeout kill | Integration test with large repo fixture |
| T4 Arbitrary code execution | Static analysis only; never run install/build scripts | Worker command audit |
| T5 SSRF via git URL | Scheme allowlist + private/link-local IP block | Unit test with `169.254.169.254` |
| T6 IDOR on findings | Every query scoped by `owner_id`/`project_id` | Authz test crossing user boundaries |
| T7 Stored XSS in snippets | Code viewer treats content as text, never raw HTML | Render `<script>` in snippet safely |
| T8 Secrets leakage in reports | Secret-detection pass + redaction in exported reports | Report diff scan |

## 6. Testing Strategy

- Unit tests for validators, normalization, fingerprint hashing.
- Integration test: seeded vulnerable fixture repo → expected CWEs detected.
- Adversarial self-test: zip-bomb, path-traversal, oversized repo, private-IP git URL against own tool.

## 7. Risk Register

- **Semgrep noise:** Mitigate by curated ruleset, not every pack.
- **Docker escape:** Blocking issue — verify resource limits before Phase 5.
- **Time overrun:** Hard freeze at end of Phase 3 (Day 9); protect Phase 5.
- **Credibility of findings:** Include at least one less-common open-source repo, not only Juice Shop/DVWA.
