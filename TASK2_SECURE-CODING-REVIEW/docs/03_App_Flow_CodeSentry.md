# Application / Product Flow
## Product: CodeSentry

---

### 1. Top-Level Navigation

```
Login/Signup
   │
   ▼
Dashboard (project list, global severity summary)
   │
   ├── + New Project ──► Add Repo (git URL / zip upload) ──► Project Detail
   │
   ├── Project Detail
   │      ├── Scan History (list of past scans, status, timestamp)
   │      ├── Trigger New Scan
   │      └── Latest Scan Summary (severity breakdown chart)
   │
   ├── Scan Detail
   │      ├── Findings List (filter: severity / CWE / OWASP category / status)
   │      ├── Finding Detail (code snippet, description, remediation, triage controls)
   │      └── Export Report (PDF/MD)
   │
   └── Settings
          ├── Ruleset configuration (which Semgrep packs active)
          └── Account
```

### 2. Core User Journey 1 — Onboard a Project & Run First Scan

1. User logs in → lands on empty Dashboard
2. Clicks "+ New Project" → chooses "Git URL" or "Upload ZIP"
3. If Git URL: backend validates scheme + blocks private IP ranges (SSRF mitigation) before queuing clone
4. If ZIP: backend validates size, entry count, path safety (zip-bomb/traversal mitigations) before extraction
5. Project created → user clicks "Run Scan"
6. Job queued (Celery) → frontend polls `/api/scans/{id}` for status: `queued → cloning → scanning-sast → scanning-sca → normalizing → complete`
7. On complete, user redirected to Scan Detail with findings populated

### 3. Core User Journey 2 — Triage Findings (the "manual review" half of the deliverable)

1. User opens Scan Detail → sees findings sorted by severity (Critical first)
2. Clicks a finding → Finding Detail shows: file path + line, code snippet (escaped/sandboxed render), CWE ID, OWASP category, Semgrep rule ID, auto-generated remediation text
3. User selects triage status: `Confirmed` / `False Positive` / `Won't Fix` / `Needs Manual Review`
4. User adds free-text reviewer notes (this is where the intern's actual security judgment is captured — required for the report to demonstrate manual review, not just tool output)
5. Triage decision saved to immutable audit log (who/when/what)
6. Dashboard severity summary updates live to reflect only `Confirmed` findings as "actionable"

### 4. Core User Journey 3 — Export Audit Report

1. From Scan Detail, user clicks "Export Report"
2. Backend generates structured report: Executive Summary → Methodology (tools used, ruleset) → Findings (Confirmed only by default, toggle to include all) → Per-finding: severity, CWE/OWASP mapping, evidence, remediation → Appendix (raw scanner output reference)
3. Report exported as PDF and Markdown — this file is what gets submitted for the internship task alongside the tool itself

### 5. Failure-Path Flows (must be handled, not just happy path)

| Scenario | Expected Flow |
|---|---|
| Scan job crashes/times out | Status → `failed`, error reason surfaced to user, retry option, job resources cleaned up (no orphaned containers) |
| Repo has 0 files matched by any ruleset | Scan completes with explicit "no applicable rules matched" state, not silently empty |
| User triages a finding, then re-scans same project | New scan creates new finding set; prior triage decisions matched by rule+location fingerprint where possible and carried forward as "previously reviewed" (avoids re-triaging identical issues every scan) |
| Upload exceeds size/zip-bomb limits | Rejected immediately at upload boundary, before any extraction/analysis — clear error, no partial processing |
