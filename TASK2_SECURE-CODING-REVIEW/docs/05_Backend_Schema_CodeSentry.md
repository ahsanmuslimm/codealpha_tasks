# Backend Schema Document
## Product: CodeSentry

---

### 1. Entity-Relationship Overview

```
User ──1:N── Project ──1:N── Scan ──1:N── Finding ──1:N── TriageEvent (audit log)
                                  │
                                  └──1:N── ScanArtifact (raw tool output reference)

Finding ──N:1── Rule (catalog of Semgrep/OSV rule metadata)
```

### 2. Table Definitions

**users**
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| email | text UNIQUE | |
| password_hash | text | bcrypt/argon2 |
| created_at | timestamptz | |

**projects**
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| owner_id | UUID FK → users.id | ownership scoping for all downstream IDOR checks |
| name | text | |
| source_type | enum(`git`,`upload`) | |
| source_ref | text | git URL or stored archive path — never used raw in shell commands (parameterized/validated) |
| created_at | timestamptz | |

**scans**
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| project_id | UUID FK → projects.id | |
| status | enum(`queued`,`cloning`,`scanning_sast`,`scanning_sca`,`normalizing`,`complete`,`failed`) | |
| started_at / completed_at | timestamptz | |
| error_message | text nullable | |
| ruleset_version | text | pins exact rule pack version used — required for reproducibility of findings |

**findings**
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans.id | |
| rule_id | text FK → rules.id | e.g. `semgrep.python.sqli.raw-query` |
| severity | enum(`critical`,`high`,`medium`,`low`,`info`) | |
| cwe_id | text | e.g. `CWE-89` |
| owasp_category | text | e.g. `A03:2021-Injection` |
| file_path | text | |
| line_start / line_end | int | |
| code_snippet | text | stored escaped; rendered as text-only client-side (never HTML) |
| description | text | |
| remediation | text | |
| fingerprint | text | hash(rule_id + file_path + normalized_snippet) — used to match findings across re-scans and carry forward triage decisions |
| status | enum(`open`,`confirmed`,`false_positive`,`wont_fix`,`needs_review`) default `open` | |
| triage_notes | text nullable | |
| triaged_by | UUID FK → users.id nullable | |
| triaged_at | timestamptz nullable | |

**triage_events** (append-only audit log — never updated/deleted)
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| finding_id | UUID FK → findings.id | |
| actor_id | UUID FK → users.id | |
| previous_status | enum | |
| new_status | enum | |
| notes | text nullable | |
| created_at | timestamptz | |

**rules** (catalog/metadata cache, synced from Semgrep/OSV rule packs)
| Column | Type | Notes |
|---|---|---|
| id | text PK | rule identifier |
| source | enum(`semgrep`,`osv`) | |
| description | text | |
| default_severity | enum | |
| cwe_id | text | |
| owasp_category | text | |

**scan_artifacts**
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id | UUID FK → scans.id | |
| type | enum(`raw_semgrep_json`,`raw_osv_json`) | |
| storage_path | text | reference to stored raw tool output, kept for auditability/reproducibility |

### 3. Key Indexing & Constraints

- `findings(scan_id, severity)` — composite index, primary query pattern (filtered/sorted list view)
- `findings(fingerprint)` — index for cross-scan triage carry-forward lookup
- `projects(owner_id)` and every child table scoped transitively by it — enforced at query layer (ORM-level scoping), not just app logic, to close the IDOR gap identified in TRD §3 (T6)
- `triage_events` has no UPDATE/DELETE grant at DB role level — enforces true immutability of the audit trail, not just app-level convention

### 4. Data Retention Note

Raw scan artifacts (full tool JSON output) retained for reproducibility of the audit report; code snippets stored in `findings` are truncated (max ~15 lines) to avoid inadvertently persisting large chunks of potentially sensitive/proprietary source code beyond what's needed to justify the finding.
