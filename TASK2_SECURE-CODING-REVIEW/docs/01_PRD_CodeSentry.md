# Product Requirement Document (PRD)
## Product: CodeSentry — Multi-Language Secure Code Review Platform

---

### 1. Problem Statement

Manual security code review does not scale: reviewers miss issues under time pressure, static analyzer output is noisy and un-triaged (high false-positive rate discourages adoption), and findings from different tools (SAST, SCA) live in disconnected silos with no unified severity model or audit trail. Teams need a **single workflow** that combines automated detection with structured human triage and produces a defensible, exportable audit report.

### 2. Goal vs Assumed Goal (explicit distinction)

- **Literal task goal:** perform a security code review of *an* application and document findings.
- **Actual goal for this deliverable:** build a working tool capable of performing that review at scale, across languages, then use it to execute real audits — demonstrating both engineering capability (build a security tool) and security capability (use it correctly, interpret results, write remediation guidance).

If the tool exists but produces no real audit output, the deliverable fails the original task. **The tool is a means, not a substitute, for the audit.** Implementation Plan (Doc 6) enforces this by reserving explicit time for real audits on real target applications.

### 3. Target Users / Personas

| Persona | Need |
|---|---|
| Security Intern (you) | Produce credible, scalable audit output; demonstrate engineering + security judgment |
| Internship Reviewer/Mentor | Verify real vulnerabilities found, correctly classified (CWE/OWASP), with actionable remediation |
| (Simulated) Dev Team consumer | Wants triaged, non-noisy findings with clear fix guidance, not a raw scanner dump |

### 4. In-Scope (MVP, 2-week build)

1. Repo ingestion (git URL clone or zip upload)
2. Automated multi-language static analysis via Semgrep engine (OWASP Top 10 / CWE-mapped ruleset)
3. Dependency vulnerability scan (SCA) via OSV-Scanner
4. Unified findings model: severity (Critical/High/Medium/Low/Info), CWE ID, OWASP category, file/line, code snippet, remediation guidance
5. Manual triage workflow: confirm / false-positive / won't-fix / needs-manual-review, with reviewer notes
6. Isolated, sandboxed scan execution (Docker per-job)
7. Exportable report (PDF/Markdown) suitable for internship submission
8. Basic auth (single-tenant is acceptable for MVP; multi-tenant is explicitly out-of-scope, see below)
9. Dashboard: project list, scan history, severity breakdown

### 5. Explicitly Out of Scope (and why — prevents scope creep)

| Feature | Reason excluded |
|---|---|
| Custom per-language parser/analyzer built from scratch | Infeasible in 2 weeks; Semgrep's existing engine is the correct integration point (see TRD) |
| Real-time IDE plugin | Separate product surface; no incremental value to the audit deliverable |
| ML/LLM-based vulnerability detection | Unverified accuracy, adds risk of hallucinated findings in a security report — credibility risk |
| Full multi-tenant SaaS (billing, org hierarchies) | Not required to prove the security/engineering skill this task tests; adds auth/IDOR surface for no grading benefit |
| Dynamic analysis / DAST / runtime execution of target code | Major additional attack surface (executing arbitrary target app code) — deliberately excluded from MVP threat model |

### 6. Success Metrics

- Tool successfully scans ≥3 real/sample applications across ≥3 different languages (e.g., JS, Python, Java) without crashing
- ≥90% of flagged findings are manually triaged (not left as raw scanner noise) — proves human review layer adds value
- Final report maps every confirmed finding to CWE + OWASP Top 10 (2021) category with remediation
- At least 1 finding per target app is a **true positive with real exploitability reasoning**, not just a lint-level nit

### 7. Key Risks to the Product Goal

- **Risk:** Building the tool consumes all 2 weeks, leaving no time for actual audits → mitigated by Implementation Plan phase gating (tool MVP frozen by end of Week 1).
- **Risk:** Semgrep default rules produce high noise → mitigated by curated ruleset (OWASP Top 10 + CWE Top 25 subset) instead of "run everything."
- **Risk:** Claiming "all languages" without substantiation → mitigated by scoping demoed languages explicitly (JS/TS, Python, Java, Go) while being technically honest that the underlying engine supports more.
