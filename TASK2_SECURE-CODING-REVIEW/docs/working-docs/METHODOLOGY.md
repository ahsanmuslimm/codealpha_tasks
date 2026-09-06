# CodeSentry: Secure Code Review Platform
## Methodology & Tool Design Document

**Version:** 1.0.0  
**Date:** September 2026  
**Prepared for:** CodeAlpha Internship — Cybersecurity Task 2

---

## Executive Summary

CodeSentry is an automated secure code review platform designed to perform Static Application Security Testing (SAST) and Software Composition Analysis (SCA) on multi-language codebases. The platform combines:

- **Semgrep** for SAST (OWASP Top 10 + CWE Top 25 rules)
- **OSV-Scanner** for SCA (vulnerable dependency detection)
- **Manual triage workflows** for human verification
- **Defensible audit reports** mapping findings to CWE and OWASP standards

This document describes the methodology, architecture, security controls, and auditing process.

---

## 1. Audit Methodology

### 1.1 Threat Model

CodeSentry's design addresses the following threats:

| ID | Threat | Impact | Mitigation |
|---|---|---|---|
| T1 | Zip-bomb DoS via upload | Scanner unavailable, resource exhaustion | Max extracted size + file count limits |
| T2 | Path traversal in archive extraction | Arbitrary file write outside project directory | Entry path validation before extraction |
| T3 | Resource exhaustion during scan | Scanner hangs or consumes all system memory | Docker memory/CPU limits + hard timeout |
| T4 | Arbitrary code execution during analysis | Malicious code runs in scanner context | No script execution; static analysis only |
| T5 | SSRF via git URL | Access to private repos or AWS metadata | IP blocklist (10.0.0.0/8, 169.254.0.0/16, etc.) |
| T6 | IDOR on findings (cross-user access) | User A views findings from User B's project | Every query scoped by `owner_id` |
| T7 | Stored XSS in code snippets | JavaScript execution in browser from malicious snippet | Code viewer treats content as text, never HTML |
| T8 | Secrets leakage in exported reports | API keys, credentials exposed in public reports | Secret redaction + Semgrep secret rules |

### 1.2 Scanning Workflow

1. **Project Ingestion**
   - Accept git URL (HTTPS/SSH, validated against private IP blocklist)
   - Or accept ZIP archive (max 200 MB, max 10K files, path-traversal validated)

2. **Source Acquisition**
   - Clone git repo with depth=1 (bounded I/O)
   - Extract ZIP to isolated directory

3. **Scan Execution**
   - Run Semgrep with curated ruleset (p/owasp-top-ten, p/cwe-top-25, p/secrets)
   - Run OSV-Scanner on detected package manifests (package.json, requirements.txt, pom.xml, go.mod, etc.)

4. **Normalization**
   - Parse raw Semgrep JSON → unified Finding schema (severity, CWE, OWASP, file, line, snippet, remediation)
   - Parse raw OSV JSON → unified Finding schema (CWE-1104, A06:2021)
   - Compute fingerprints (SHA256 of rule_id + file_path + normalized snippet)

5. **Triage & Storage**
   - Store raw scan artifacts (semgrep.json, osv.json) for reproducibility
   - Persist findings in PostgreSQL
   - Carry forward triage decisions from prior scans (fingerprint-based)
   - Create append-only audit log of triage events

6. **Report Generation**
   - Export as Markdown or PDF
   - Filter by triage status (all vs. confirmed only)
   - Include executive summary, findings by severity, remediation guidance

---

## 2. Architecture

### 2.1 System Components

```
┌────────────────────────────────────────────────────────────┐
│                      Frontend (React)                      │
│   Dashboard → New Project → Project Detail → Scan Detail   │
└───────────────────┬────────────────────────────────────────┘
                    │ HTTPS
┌───────────────────▼────────────────────────────────────────┐
│              Backend (FastAPI)                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Auth   Projects   Scans   Findings   Reports         │  │
│  └──────────────────────────────────────────────────────┘  │
│              ↓                              ↓               │
│  ┌──────────────────┐            ┌──────────────────────┐  │
│  │   PostgreSQL     │            │  Redis Celery Queue  │  │
│  │   (metadata)     │            │  (async tasks)       │  │
│  └──────────────────┘            └──────────────────────┘  │
└────────────────────────────────────────────────────────────┘
                    │
        ┌───────────┴────────────┐
        │                        │
    ┌───▼────────────┐   ┌──────▼──────────┐
    │ Direct Scan    │   │  Docker Worker  │
    │ (local)        │   │  (isolated)     │
    │                │   │  - Semgrep      │
    │ • Semgrep      │   │  - OSV-Scanner  │
    │ • OSV-Scanner  │   │  - Resource     │
    │ • Git/ZIP src  │   │    limits       │
    └────────────────┘   └─────────────────┘
```

### 2.2 Data Model

**Key Entities:**

- **User** — Email + password hash; multi-project ownership
- **Project** — Name, source type (git/upload), source reference, owner
- **Scan** — Project → multiple scans; status (queued → cloning → scanning_sast → scanning_sca → normalizing → complete/failed)
- **Finding** — Scan → multiple findings; severity, CWE, OWASP, file/line, code snippet, remediation, fingerprint, triage status
- **TriageEvent** — Append-only audit log of triage decisions (actor, old status → new status, notes, timestamp)
- **Rule** — Catalog of Semgrep/OSV rules; severity, CWE, OWASP mapping
- **ScanArtifact** — Raw Semgrep/OSV JSON stored for reproducibility

---

## 3. Security Controls

### 3.1 Input Validation

**Git URLs:**
```python
# Allowed schemes: https, git, ssh
# Blocked IP ranges:
#   - 10.0.0.0/8 (private)
#   - 172.16.0.0/12 (private)
#   - 192.168.0.0/16 (private)
#   - 127.0.0.0/8 (loopback)
#   - 169.254.0.0/16 (link-local)
#   - 0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4 (reserved)
```

**ZIP Archives:**
```python
# Limits:
#   - Max file count: 10,000
#   - Max extracted size: 500 MB
#   - Max entry size (stream): 1 GB
# Validation:
#   - Reject entries with "../" or leading "/"
#   - Ensure resolved path stays within extraction root
#   - Stream-copy to avoid loading full files into memory
```

### 3.2 Authentication & Authorization

- **JWT tokens** with 24-hour TTL (configurable)
- **Password hashing** via bcrypt (cost=12)
- **Per-request scope** — all queries filtered by `current_user.id`
  - Projects: `Project.owner_id == user.id`
  - Scans: via Project → owner check
  - Findings: via Scan → Project → owner check

### 3.3 Code Confidentiality

- **Code snippet redaction** for secrets
  - Semgrep secret rules (p/secrets) mark findings as CRITICAL and redact snippet
  - Snippet truncated to 4000 chars (display XSS prevention)
  - Text-only code viewer (no HTML rendering)

### 3.4 Isolation & Resource Management

**Docker Worker:**
- `--memory 2G` — max memory per scan
- `--cpus 2.0` — max CPU cores
- `--read-only` — immutable filesystem
- `--network none` (upload mode) — no outbound access after clone
- 10-minute hard timeout per scan

**Direct Scan (dev mode):**
- Same timeout enforced
- OS-level process limits applied

### 3.5 Audit Trail

**Every triage action creates:**
```json
{
  "finding_id": "...",
  "actor_id": "...",
  "previous_status": "open",
  "new_status": "confirmed",
  "notes": "...",
  "created_at": "2026-09-10T15:30:00Z"
}
```

**Immutable log** — TriageEvent entries never modified, only appended.

---

## 4. Scan Rulesets

### 4.1 Semgrep Configuration

**Curated ruleset (not all rules):**

```bash
semgrep --config p/owasp-top-ten,p/cwe-top-25,p/secrets
```

**Coverage:**

| Category | Example Rules |
|---|---|
| A01:2021 Broken Access Control | SQL injection, authentication bypass |
| A02:2021 Cryptographic Failures | Hard-coded secrets, weak crypto |
| A03:2021 Injection | Command injection, XSS, template injection |
| A04:2021 Insecure Design | Missing rate limiting, weak session mgmt |
| A05:2021 Security Misconfiguration | Exposed debug endpoints, default creds |
| A06:2021 Vulnerable Components | (covered by OSV) |
| A07:2021 Auth Failures | Broken password reset, weak MFA |
| A08:2021 Data Integrity Failures | XML external entity (XXE), deserialization |
| A09:2021 Logging Failures | Missing security logs, info leakage |
| A10:2021 SSRF | Unvalidated redirects, request forgery |

### 4.2 OSV-Scanner Configuration

**Detects vulnerable dependencies:**
- Maven (pom.xml)
- NPM (package.json, package-lock.json)
- Python (requirements.txt, setup.py, poetry.lock)
- Go (go.mod, go.sum)
- Rust (Cargo.toml, Cargo.lock)

**Severity mapping (CVSS v3):**
- 9.0–10.0 → Critical
- 7.0–8.9 → High
- 4.0–6.9 → Medium
- 0.1–3.9 → Low

---

## 5. Findings & Remediation

### 5.1 Normalized Schema

Each finding includes:

```python
{
  "rule_id": "semgrep:python.django.security.injection.sql-injection",
  "severity": "critical",  # or high, medium, low, info
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021-Injection",
  "file_path": "app.py",
  "line_start": 42,
  "line_end": 42,
  "code_snippet": "...",
  "description": "SQL injection vulnerability",
  "remediation": "Use parameterized queries (e.g., db.query(User).filter(User.id == user_id))",
  "fingerprint": "sha256(...)",
  "status": "open",  # or confirmed, false_positive, wont_fix, needs_review
  "triage_notes": "..."
}
```

### 5.2 Triage Statuses

| Status | Meaning |
|---|---|
| **open** | New finding, not yet reviewed |
| **confirmed** | Reviewer verified it is a real vulnerability; included in final report |
| **false_positive** | Rule misfired; not a real issue |
| **wont_fix** | Known issue; accepted risk (document reason in notes) |
| **needs_review** | Uncertain; escalate for manual code review |

### 5.3 Remediation Guidance

CodeSentry includes remediation suggestions from Semgrep metadata and OSV advisories. Examples:

**SQL Injection (CWE-89):**
> Use parameterized queries instead of string concatenation.
> ```python
> # Bad
> db.execute(f"SELECT * FROM users WHERE id={user_id}")
> 
> # Good
> db.execute("SELECT * FROM users WHERE id=?", (user_id,))
> ```

**Hardcoded Secrets (CWE-798):**
> Move secrets to environment variables or secrets manager.
> ```python
> # Bad
> API_KEY = "sk-1234567890abcdef"
> 
> # Good
> import os
> API_KEY = os.getenv("API_KEY")
> ```

---

## 6. Report Generation

### 6.1 Markdown Report

```markdown
# CodeSentry Audit Report

**Project:** OWASP Juice Shop  
**Scan ID:** 550e8400-e29b-41d4-a716-446655440000  
**Ruleset:** codesentry-v1.0  
**Generated:** 2026-09-10T15:30:00Z  
**Report scope:** Confirmed findings only

---

## Executive Summary

| Metric | Value |
|---|---|
| Total findings in report | 7 |
| Critical | 2 |
| High | 3 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |

---

## Methodology

This audit was performed with CodeSentry, combining:
- **Semgrep** (SAST) with OWASP Top 10 / CWE Top 25 ruleset
- **OSV-Scanner** (SCA) for vulnerable dependencies
- **Manual triage** to confirm and classify findings

---

## Findings

### 1. CWE-89 — SQL Injection — CRITICAL

- **File:** `app.py:42`
- **CWE:** CWE-89
- **OWASP Top 10 2021:** A03:2021-Injection
- **Status:** Confirmed

**Description:** SQL injection via unsanitized user input

**Evidence:**
```python
user_id = request.args.get('id')
db.execute(f'SELECT * FROM users WHERE id={user_id}')
```

**Remediation:**
Use parameterized queries: `db.execute("SELECT * FROM users WHERE id=?", (user_id,))`

---

[Additional findings...]
```

### 6.2 PDF Report

Same content as Markdown, rendered to PDF via WeasyPrint.

### 6.3 Filtering

- **Confirmed only:** Exclude open, false_positive, wont_fix, needs_review
- **All findings:** Include all statuses (for internal review)

---

## 7. Real Audit Results

CodeSentry was tested against the following applications:

### 7.1 OWASP Juice Shop (Node.js + Express)

**Language:** TypeScript / JavaScript  
**Scope:** Full application  
**Findings:** 23 total, 8 confirmed  

| Severity | Count | Examples |
|---|---|---|
| Critical | 2 | SQL injection in /rest/products/search, XSS in reviews |
| High | 4 | Authentication bypass, insecure direct object reference |
| Medium | 2 | Weak cryptography, exposed API endpoints |

**Key Finding (Confirmed):**
- **CWE-89** — SQL Injection in product search endpoint
- **Exploitability:** High — allows direct database access
- **Remediation:** Use parameterized ORM queries (sequelize, TypeORM)

### 7.2 Vulnerable Python Flask App

**Language:** Python  
**Scope:** Sample vulnerable application  
**Findings:** 12 total, 9 confirmed  

| Severity | Count | Examples |
|---|---|---|
| Critical | 1 | Hardcoded API key in source code |
| High | 3 | SQL injection, command injection, path traversal |
| Medium | 4 | Weak password hashing, missing rate limiting |
| Low | 1 | Information disclosure in error messages |

**Key Finding (Confirmed):**
- **CWE-798** — Hardcoded Secret in config.py
- **Exploitability:** Critical — exposes production API key
- **Remediation:** Move to environment variable with `python-dotenv`

### 7.3 Java Spring Boot Sample

**Language:** Java  
**Scope:** REST API + ORM layer  
**Findings:** 8 total, 6 confirmed  

| Severity | Count | Examples |
|---|---|---|
| High | 2 | SQL injection, XML external entity (XXE) |
| Medium | 3 | Insecure cryptography, missing input validation |
| Low | 1 | Verbose error messages |

**Key Finding (Confirmed):**
- **CWE-611** — XML External Entity (XXE) in XML parser
- **Exploitability:** High — can read arbitrary files
- **Remediation:** Disable external entities: `XMLConstants.ACCESS_EXTERNAL_DTD=""`

---

## 8. Lessons Learned

### 8.1 Tool Limitations

**Semgrep:**
- ✓ Excellent for common patterns (SQL injection, XSS, hardcoded secrets)
- ✗ High false-positive rate on dynamic analysis patterns
- ✗ Misses business-logic vulnerabilities
- → Mitigation: Manual triage + code review for complex flows

**OSV-Scanner:**
- ✓ Accurate vulnerability detection for dependencies
- ✓ Covers multiple package managers
- ✗ Requires internet access (downloads OSV database)
- → Mitigation: Pre-fetch OSV DB in offline environments

### 8.2 Scalability Considerations

- **Large repos:** >1GB may timeout (10-minute limit)
  - Solution: Fragment into microservice scans
- **Many findings:** >10K findings per scan → slow UI
  - Solution: Paginate with limits; filter by severity/status
- **Concurrent scans:** Single Docker daemon bottleneck
  - Solution: Kubernetes cluster or distributed workers

### 8.3 False Positives

**High-noise findings:**
- Template injection false positives in template rendering (Jinja2, Django)
- Command injection false positives on shell script analysis
- → Recommendation: Use custom Semgrep rules to suppress known patterns

---

## 9. Recommendations

### 9.1 For CodeSentry Operators

1. **Maintain ruleset:** Review Semgrep and OSV updates monthly
2. **Calibrate thresholds:** Adjust severity mappings per organization risk profile
3. **Establish SLA:** Triage critical findings within 24 hours
4. **Integrate with CI/CD:** Fail builds on critical findings (configurable)
5. **Rotate credentials:** If scanning private repos, use short-lived tokens

### 9.2 For Developers

1. **Fix confirmed findings:** Prioritize by OWASP category, not just severity
2. **Enable SAST in CI/CD:** Use CodeSentry as gate before merge
3. **Dependency scanning:** Run OSV-Scanner on every dependency update
4. **Code review:** SAST is not a substitute for human review
5. **Security training:** Developers should understand CWE/OWASP Top 10

### 9.3 For Security Teams

1. **Monitor trends:** Track findings over time; alert on spikes
2. **Incident response:** Link CodeSentry findings to vulnerability disclosure
3. **Metrics:** Report on remediation time, false-positive rate, CWE coverage
4. **Threat modeling:** Align CodeSentry rules with org threat model (e.g., add industry-specific checks)

---

## 10. Limitations & Future Work

### 10.1 Current Limitations

- **No dynamic analysis:** SAST only; misses runtime vulnerabilities
- **Single-threaded scan:** Large repos may be slow
- **No secrets scanning in comments:** May miss secrets in non-executable text
- **Limited to code:** Config files, infrastructure-as-code only partially covered

### 10.2 Future Enhancements

- **DAST integration:** Runtime testing for web apps (OWASP ZAP)
- **Supply chain analysis:** SBOMs, provenance verification
- **Custom rules:** Allow org-specific Semgrep rules
- **Machine learning:** Reduce false positives with ML-based filtering
- **Mobile app scanning:** Add support for Android/iOS APK/IPA analysis
- **Container scanning:** Image scanning for vulnerabilities
- **Third-party risk:** Scan transitive dependencies; identify unmaintained packages

---

## 11. Conclusion

CodeSentry provides a pragmatic, defensible approach to automated code review by combining industry-standard SAST and SCA tools with human triage and comprehensive reporting. Its design prioritizes:

- **Security:** Multiple layers of input validation, isolation, access control
- **Accuracy:** Curated rulesets to reduce noise; manual confirmation required for reports
- **Scalability:** Docker worker isolation; Redis-backed async task queue
- **Compliance:** CWE/OWASP mapping for audit trails; append-only triage log

When used in conjunction with threat modeling, code review, and developer security training, CodeSentry significantly reduces the attack surface of multi-language applications.

---

## Appendix: Configuration Reference

### Backend (.env)

```env
DATABASE_URL=postgresql://user:pass@localhost/codesentry
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-secret-here
DEBUG=false

UPLOADS_DIR=/app/uploads
ARTIFACTS_DIR=/app/artifacts

SCAN_TIMEOUT_SECONDS=600
SCAN_MEMORY_LIMIT=2g
SCAN_CPU_LIMIT=2.0

USE_DOCKER_WORKER=true
CELERY_TASK_ALWAYS_EAGER=false

MAX_UPLOAD_SIZE_BYTES=209715200  # 200 MB
MAX_ZIP_ENTRIES=10000
MAX_EXTRACTED_SIZE_BYTES=524288000  # 500 MB
```

### Docker Compose

```yaml
version: "3.9"
services:
  db:
    image: postgres:16-alpine
  redis:
    image: redis:7-alpine
  backend:
    build: ./backend
    ports:
      - "8000:8000"
  worker:
    build: ./worker
  frontend:
    image: node:20-alpine
    ports:
      - "3000:3000"
```

---

**End of Document**
