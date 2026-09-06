import hashlib
import json
from pathlib import Path
from typing import List

from app.models import ArtifactType, Finding, Rule, RuleSource, Severity


# Map Semgrep severity strings to our enum.
_SEMGREP_SEVERITY = {
    "ERROR": Severity.high,
    "WARNING": Severity.medium,
    "INFO": Severity.low,
}

# Map OWASP IDs to 2021 category names.
_OWASP_CATEGORIES = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery",
}


def _extract_cwe(metadata: dict) -> str:
    cwe = metadata.get("cwe", [])
    if cwe:
        return cwe[0].split(":")[0] if ":" in cwe[0] else cwe[0]
    owasp = metadata.get("owasp", [])
    if owasp:
        # Try to derive a CWE from owasp mapping if possible; otherwise leave blank.
        return ""
    return ""


def _extract_owasp(metadata: dict) -> str:
    owasp = metadata.get("owasp", [])
    if owasp:
        code = owasp[0].split(":")[0]
        return _OWASP_CATEGORIES.get(code, owasp[0])
    return ""


def _make_fingerprint(rule_id: str, file_path: str, snippet: str) -> str:
    normalized = " ".join(snippet.split())
    data = f"{rule_id}|{file_path}|{normalized}"
    return hashlib.sha256(data.encode()).hexdigest()


def normalize_semgrep(semgrep_json_path: str) -> List[Finding]:
    findings: List[Finding] = []
    path = Path(semgrep_json_path)
    if not path.exists():
        return findings

    data = json.loads(path.read_text())
    for result in data.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        rule_id = result.get("check_id", "semgrep.unknown")
        file_path = result.get("path", "")
        line_start = result.get("start", {}).get("line")
        line_end = result.get("end", {}).get("line")
        snippet = result.get("extra", {}).get("lines", "")
        message = result.get("extra", {}).get("message", "")
        severity = _SEMGREP_SEVERITY.get(
            result.get("extra", {}).get("severity", "WARNING"), Severity.medium
        )

        # Secrets rules get critical severity and redacted snippet.
        if "secrets" in rule_id.lower() or "secret" in message.lower():
            severity = Severity.critical
            snippet = "[REDACTED - potential secret detected]"

        cwe = _extract_cwe(metadata)
        owasp = _extract_owasp(metadata)

        findings.append(Finding(
            rule_id=_rule_id(rule_id, RuleSource.semgrep),
            severity=severity,
            cwe_id=cwe,
            owasp_category=owasp,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet[:4000],
            description=message,
            remediation=metadata.get("fix", ""),
            fingerprint=_make_fingerprint(rule_id, file_path, snippet),
        ))
    return findings


def _osv_severity(severity_obj: dict) -> Severity:
    """Map an OSV severity entry to our Severity enum.

    OSV format can be:
      {"type": "CVSS_V3", "score": 9.5}          # score is a float directly
      {"type": "CVSS_V3", "score": {"score": 9.5}} # score nested (some older feeds)
    """
    if not severity_obj:
        return Severity.medium
    raw = severity_obj.get("score", 0)
    # Handle both float and nested-dict forms.
    if isinstance(raw, dict):
        score = float(raw.get("score", 0))
    else:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = 0.0
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    return Severity.low


def normalize_osv(osv_json_path: str) -> List[Finding]:
    findings: List[Finding] = []
    path = Path(osv_json_path)
    if not path.exists():
        return findings

    data = json.loads(path.read_text())
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            for vuln in pkg.get("vulnerabilities", []):
                severity = Severity.medium
                for s in vuln.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        severity = _osv_severity(s.get("score", {}))
                        break

                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
                rule_id = f"osv.{pkg.get('package', {}).get('name', 'unknown')}:{cve_id}"
                file_path = result.get("source", {}).get("path", "")
                description = vuln.get("summary", vuln.get("details", "Vulnerable dependency"))

                findings.append(Finding(
                    rule_id=_rule_id(rule_id, RuleSource.osv),
                    severity=severity,
                    cwe_id="CWE-1104",  # Use of Unmaintained Third-Party Components
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    file_path=file_path,
                    line_start=None,
                    line_end=None,
                    code_snippet=f"Package: {pkg.get('package', {}).get('name')} "
                                 f"Version: {pkg.get('package', {}).get('version')}",
                    description=description,
                    remediation=f"Upgrade to a non-vulnerable version. See {vuln.get('id')}",
                    fingerprint=_make_fingerprint(rule_id, file_path, description),
                ))
    return findings


def _rule_id(raw_id: str, source: RuleSource) -> str:
    """Return a stable rule id and ensure a Rule catalog row exists."""
    stable = f"{source.value}:{raw_id}"[:255]
    return stable


def ensure_rules(db, findings: List[Finding]) -> None:
    """Create Rule catalog rows for any unseen rule ids."""
    from app.models import Rule

    seen = set()
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        existing = db.query(Rule).filter(Rule.id == f.rule_id).first()
        if existing:
            continue
        source = RuleSource.semgrep if f.rule_id.startswith("semgrep:") else RuleSource.osv
        db.add(Rule(
            id=f.rule_id,
            source=source,
            description=f.description[:500],
            default_severity=f.severity,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
        ))
    db.commit()
