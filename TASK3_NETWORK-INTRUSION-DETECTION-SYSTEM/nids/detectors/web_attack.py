"""Signature-driven web attack detection (SQLi, XSS, traversal, RCE, Log4Shell)."""

from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from nids.alert import Alert, CAT_WEB
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta

# (name, compiled regex, severity, description hint)
PATTERNS: List[Tuple[str, re.Pattern, int]] = [
    ("SQL injection - UNION SELECT",
     re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE), 3),
    ("SQL injection - tautology",
     re.compile(r"(?:'|%27|\b)\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE), 3),
    ("SQL injection - stacked/time-based",
     re.compile(r"(?:;\s*drop\s+table|sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay)",
                re.IGNORECASE), 3),
    ("XSS - script tag",
     re.compile(r"<\s*script\b", re.IGNORECASE), 2),
    ("XSS - event handler",
     re.compile(r"\bon(?:error|load|click|mouseover|focus)\s*=", re.IGNORECASE), 2),
    ("XSS - javascript URI",
     re.compile(r"javascript\s*:", re.IGNORECASE), 2),
    ("Path traversal - dot segments",
     re.compile(r"(?:\.\.[\\/]){2,}|%2e%2e(?:%2f|/|%5c|\\)", re.IGNORECASE), 2),
    ("Path traversal - sensitive file",
     re.compile(r"/etc/(?:passwd|shadow)|boot\.ini|win\.ini|/proc/self/environ",
                re.IGNORECASE), 3),
    ("Command injection",
     re.compile(r"(?:;|\||&&)\s*(?:cat|id|whoami|wget|curl|nc|bash|sh|ping)\b|"
                r"\$\(\s*(?:id|whoami|cat)\s*\)", re.IGNORECASE), 3),
    ("Log4Shell JNDI lookup (CVE-2021-44228)",
     re.compile(r"\$\{\s*(?:jndi|lower|upper|env)\s*:", re.IGNORECASE), 4),
    ("Shellshock bash injection",
     re.compile(r"\(\)\s*\{[^}]*;\s*\}", re.IGNORECASE | re.DOTALL), 3),
    ("Webshell / PHP code execution",
     re.compile(r"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)|system\s*\(\s*\$_(?:GET|POST|REQUEST)",
                re.IGNORECASE), 3),
]


class WebAttackDetector(BaseDetector):
    """Inspects HTTP requests for malicious payloads.

    Works on the best-effort parsed HTTP layer (requests and responses) and
    falls back to raw payload inspection for TCP traffic on HTTP-ish ports.
    URL-encoded input is decoded before matching to catch evasion attempts.
    """

    config_key = "web_attack"
    name = "web_attack"
    category = CAT_WEB

    HTTP_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}

    def __init__(self, config):
        super().__init__(config)
        self.cooldown = float(self.detector_cfg.get("cooldown_seconds", 10))
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        text = self._attack_surface(meta)
        if not text:
            return []
        decoded = self._decode_variants(text)
        for name, pattern, severity in PATTERNS:
            match = pattern.search(decoded) or pattern.search(text)
            if not match:
                continue
            key = f"{meta.src_ip}|{name}"
            if meta.timestamp - self._last_alert.get(key, 0.0) < self.cooldown:
                return []
            self._last_alert[key] = meta.timestamp
            snippet = match.group(0)[:80]
            return [self.make_alert(
                msg=f"WEB ATTACK: {name}",
                severity=severity,
                meta=meta,
                details=f"matched payload: {snippet!r}",
                category=CAT_WEB,
            )]
        return []

    # ------------------------------------------------------------------

    @classmethod
    def _attack_surface(cls, meta: PacketMeta) -> str:
        if meta.http and meta.http.get("is_request"):
            parts = [meta.http.get("path", ""), meta.http.get("body", ""),
                     meta.http.get("user_agent", ""), meta.http.get("host", "")]
            for value in (meta.http.get("headers") or {}).values():
                parts.append(str(value))
            return "\n".join(p for p in parts if p)
        if meta.protocol == "TCP" and meta.dst_port in cls.HTTP_PORTS and meta.payload:
            sample = meta.payload_text
            if sample[:4].upper().startswith(("GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC")):
                return sample
        return ""

    @staticmethod
    def _decode_variants(text: str) -> str:
        once = urllib.parse.unquote_plus(text)
        twice = urllib.parse.unquote_plus(once)
        return text + "\n" + once + "\n" + twice
