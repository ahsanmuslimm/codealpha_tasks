# Implementation Plan
## Product: CodeSentry — 2+ Week Build

---

### 0. Hard Constraint (from PRD §7)

The tool must be feature-frozen by end of **Week 1** so Week 2+ has guaranteed time for real audits — the actual internship deliverable. If you're still building core scan functionality past Day 7, cut UI polish before you cut audit time.

---

### Phase 1 — Days 1–3: Backend Core

- [ ] Set up FastAPI project structure, PostgreSQL schema (Doc 5) via Alembic migrations
- [ ] Implement `projects` CRUD + git-URL validation (SSRF mitigation: block private/link-local IPs, allowlist scheme)
- [ ] Implement ZIP upload endpoint with size/entry-count/path-traversal validation (T1/T2 from TRD)
- [ ] Set up Celery + Redis job queue
- [ ] Docker image for scan worker: Semgrep + OSV-Scanner installed, non-root user, no persistent network beyond clone step

**Exit criteria:** can create a project and trigger a scan job that reaches `queued` state reliably.

### Phase 2 — Days 4–6: Scan Engine Integration

- [ ] Worker: clone repo (git) or extract archive (zip) inside sandboxed container, with resource limits (`--memory`, `--cpus`, timeout)
- [ ] Run Semgrep with curated ruleset (OWASP Top 10 + CWE Top 25 subset — not "auto everything," to control noise per PRD §7 risk)
- [ ] Run OSV-Scanner against detected manifest files (package.json, requirements.txt, pom.xml, go.mod)
- [ ] Normalize both tool outputs into unified `findings` schema (severity mapping, CWE/OWASP tagging, fingerprint hash)
- [ ] Persist raw tool output as `scan_artifacts` (reproducibility)

**Exit criteria:** running a scan against a known-vulnerable sample repo (e.g., OWASP Juice Shop) produces populated, correctly-classified findings in the DB.

### Phase 3 — Days 7–9: Triage Workflow + API

- [ ] Findings list/filter API (severity, CWE, status, pagination)
- [ ] Triage PATCH endpoint + `triage_events` audit log write (append-only, enforced at DB role level)
- [ ] Fingerprint-based carry-forward logic for re-scans
- [ ] Report generation endpoint (PDF via e.g. WeasyPrint, Markdown export)

**Exit criteria:** feature freeze — backend fully functional via API/Postman even before frontend exists.

### Phase 4 — Days 10–12: Frontend

- [ ] Dashboard, Project Detail, Scan Detail/Findings List, Finding Detail slide-over, Report Export view (Doc 4 screens, in priority order — cut Settings screen polish first if time-constrained)
- [ ] Auth (JWT login)
- [ ] Poll-based scan status UI

**Exit criteria:** full user journey (Doc 3) walkable end-to-end in browser.

### Phase 5 — Days 13–14+: Real Audits (the actual internship deliverable)

- [ ] Run CodeSentry against **≥3 real applications across ≥3 languages** — recommend: OWASP Juice Shop (JS/TS), a Python Flask/Django sample with known CVEs, a Java Spring sample (or a real small open-source repo you have permission to audit)
- [ ] Manually triage every Critical/High finding — this is where your actual security judgment gets documented (false-positive reasoning, exploitability notes, business-impact framing)
- [ ] Export final audit report per target
- [ ] Write a short "Methodology & Tool Design" cover document explaining architecture decisions (this doubles as your TRD summary for the internship reviewer)

**Exit criteria (internship submission):** the tool (code + architecture docs) + 3 real audit reports with confirmed findings, CWE/OWASP mapping, and remediation guidance.

---

### Testing Strategy (parallel, not a separate phase)

- Unit tests: finding normalization logic, fingerprint hashing, SSRF/path-traversal validators (these are security controls — they need tests, not just implementation)
- Integration test: full pipeline against a small fixture repo with 1–2 deliberately seeded vulnerabilities of known CWE type — assert they're detected and correctly classified
- Adversarial self-test (per your framework's "Adversarial Mode"): attempt zip-bomb upload, path-traversal filename, oversized repo, private-IP git URL against your own tool before calling it done — if any of T1–T8 (TRD §3) aren't actually mitigated, fix before Phase 5

### Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Semgrep ruleset too noisy, triage takes too long | Medium | High (eats into Phase 5 time) | Curate ruleset tightly in Phase 2; don't run every available rule pack |
| Docker sandboxing misconfigured, scan container escapes limits | Low | Critical | Explicit resource-limit tests before Phase 5, treat as blocking |
| Running out of time before real audits | Medium | Critical (fails literal task requirement) | Hard Phase 1-3 freeze deadline (Day 9), Phase 5 is non-negotiable and protected |
| Target sample apps too well-known (findings look copy-pasted from public writeups) | Medium | Medium (credibility) | Include at least one less-common/real small open-source repo, not only Juice Shop/DVWA |
