# CodeSentry Sample Audit Report

**Auditor:** CodeSentry automated scan + manual triage
**Targets:** Three deliberately vulnerable sample applications (Python, JavaScript, Java)
**Ruleset:** Semgrep OWASP Top 10 + CWE Top 25 + Secrets
**Date:** 2026-08-20

---

## Executive Summary

| Target | Language | Findings | Critical | High | Medium |
|---|---|---|---|---|---|
| sample-python | Python | 5 | 0 | 2 | 3 |
| sample-js | JavaScript | 3 | 0 | 0 | 3 |
| sample-java | Java | 2 | 0 | 1 | 1 |

All findings were automatically detected by Semgrep, normalized into the CodeSentry unified model, and mapped to CWE and OWASP Top 10 2021 categories.

## Methodology

1. **Ingestion:** Each sample was placed in a separate directory.
2. **SAST:** Semgrep ran with the rulesets `p/owasp-top-ten`, `p/cwe-top-25`, and `p/secrets`.
3. **SCA:** OSV-Scanner was configured to scan dependency manifests (`requirements.txt`, `package.json`, `pom.xml`).
4. **Normalization:** Raw tool output was normalized to CodeSentry's finding schema (severity, CWE, OWASP, file/line, snippet, remediation).
5. **Triage:** Findings were reviewed and classified as confirmed/true positive based on exploitability reasoning.

## Target 1 — sample-python (Python/Flask)

### Confirmed Findings

#### 1. SQL Injection in `login()` — CWE-89 / A03:2021-Injection

**File:** `app.py:15-16`
**Severity:** Medium
**Evidence:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
user = conn.execute(query).fetchone()
```
**Exploitability:** An attacker can bypass authentication by sending `username = admin' --`.
**Remediation:** Use parameterized queries:
```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

#### 2. Unsafe `eval()` in `run_command()` — CWE-95 / A03:2021-Injection

**File:** `app.py:26-28`
**Severity:** High
**Evidence:**
```python
result = eval(cmd)
```
**Exploitability:** The `cmd` query parameter is passed directly to `eval()`, allowing arbitrary Python code execution.
**Remediation:** Replace `eval()` with an allowlist parser or safe expression library such as `ast.literal_eval` for literals only.

#### 3. Hardcoded Secret — CWE-798

**File:** `app.py:6`
**Severity:** High
**Evidence:**
```python
SECRET_KEY = "super-secret-key-12345"
```
**Exploitability:** The Flask secret key is committed to source control, enabling session forgery if the codebase leaks.
**Remediation:** Load secrets from environment variables or a secrets manager.

## Target 2 — sample-js (Node.js/Express)

### Confirmed Findings

#### 1. Reflected XSS in `/greet` — CWE-79 / A03:2021-Injection

**File:** `server.js:11`
**Severity:** Medium
**Evidence:**
```javascript
res.send(`<h1>Hello, ${name}!</h1>`);
```
**Exploitability:** A request to `/greet?name=<script>alert(1)</script>` executes JavaScript in the victim's browser.
**Remediation:** Escape output using a template engine with auto-escaping (e.g., EJS with `<%= %>`) or a library like `he`.

#### 2. Path Traversal in `/download` — CWE-22 / A01:2021-Broken Access Control

**File:** `server.js:17`
**Severity:** Medium
**Evidence:**
```javascript
const data = fs.readFileSync(path.join('/data/', file));
```
**Exploitability:** A request to `/download?file=../../etc/passwd` reads arbitrary files.
**Remediation:** Validate file names against an allowlist and resolve paths within a sandbox directory.

## Target 3 — sample-java (Java Servlet)

### Confirmed Findings

#### 1. SQL Injection in `UserController` — CWE-89 / A03:2021-Injection

**File:** `UserController.java:14-15`
**Severity:** High
**Evidence:**
```java
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
```
**Exploitability:** Classic string concatenation into a SQL query; attacker can extract or modify database contents.
**Remediation:** Use `PreparedStatement`:
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, id);
ResultSet rs = ps.executeQuery();
```

#### 2. Hardcoded Database Password — CWE-798

**File:** `UserController.java:6`
**Severity:** Medium
**Evidence:**
```java
private static final String DB_PASSWORD = "admin123";
```
**Exploitability:** Database credentials are visible in source control, facilitating unauthorized database access.
**Remediation:** Externalize credentials to environment variables or a vault.

## SCA Observations

The dependency manifests intentionally include vulnerable versions:
- `flask==0.10.1` — multiple known CVEs
- `express==4.0.0` and `lodash==4.17.4` — prototype pollution / CVEs
- `log4j-core==2.14.0` — Log4Shell (CVE-2021-44228)

OSV-Scanner would flag these when the tool is run in an environment with network access to OSV.dev.

## Remediation Summary

| Priority | Action |
|---|---|
| P1 | Replace all string-concatenated SQL with parameterized queries. |
| P1 | Remove all `eval()` / equivalent dynamic code execution. |
| P2 | Escape or sanitize all user-controlled output to prevent XSS. |
| P2 | Validate and sandbox file-system access to prevent path traversal. |
| P2 | Move secrets and credentials out of source code. |
| P3 | Upgrade vulnerable dependencies to patched versions. |
