"""Alert model: severity scale, categories and the dataclass persisted to SQLite."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

SEVERITY_NAMES: Dict[int, str] = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Categories (aligned with common Suricata classtype families)
CAT_RECON = "Reconnaissance"
CAT_BRUTE_FORCE = "Brute Force"
CAT_DOS = "Denial of Service"
CAT_WEB = "Web Attack"
CAT_MALWARE = "Malware/C2"
CAT_EXFIL = "Data Exfiltration"
CAT_MITM = "MITM/Spoofing"
CAT_POLICY = "Policy Violation"
CAT_ANOMALY = "Anomaly"
CAT_SIGNATURE = "Signature"
CAT_ADMIN = "Attempted Admin"
CAT_EXPLOIT = "Exploit"

VALID_CATEGORIES = {
    CAT_RECON, CAT_BRUTE_FORCE, CAT_DOS, CAT_WEB, CAT_MALWARE,
    CAT_EXFIL, CAT_MITM, CAT_POLICY, CAT_ANOMALY, CAT_SIGNATURE,
    CAT_ADMIN, CAT_EXPLOIT,
}

ACTION_LOGGED = "logged"
ACTION_BLOCKED = "blocked"


@dataclass
class Alert:
    """One detection event."""

    timestamp: float = field(default_factory=time.time)
    name: str = "Unnamed alert"
    category: str = CAT_ANOMALY
    severity: int = 1                      # 1 Low .. 4 Critical
    detector: str = "generic"              # source detector / rule engine
    protocol: str = "OTHER"
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    details: str = ""
    sid: Optional[int] = None              # signature id (rule based alerts)
    action: str = ACTION_LOGGED            # updated by the response engine
    alert_id: Optional[int] = None         # set after DB insert

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.alert_id,
            "timestamp": self.timestamp,
            "time": self.time_iso(),
            "severity": self.severity,
            "severity_name": SEVERITY_NAMES.get(self.severity, "?"),
            "category": self.category,
            "name": self.name,
            "detector": self.detector,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "details": self.details,
            "sid": self.sid,
            "action": self.action,
        }

    def time_iso(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))

    def row(self) -> tuple:
        return (
            self.timestamp, self.time_iso(), self.sid, self.name, self.category,
            self.severity, self.protocol, self.src_ip, self.src_port,
            self.dst_ip, self.dst_port, self.details, self.detector, self.action,
        )

    @classmethod
    def from_row(cls, row: tuple) -> "Alert":
        (alert_id, ts, ts_iso, sid, name, category, severity, protocol,
         src_ip, src_port, dst_ip, dst_port, details, detector, action) = row
        return cls(
            alert_id=alert_id, timestamp=ts, name=name or "", category=category or CAT_ANOMALY,
            severity=int(severity or 1), protocol=protocol or "OTHER", src_ip=src_ip,
            src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, details=details or "",
            detector=detector or "generic", sid=sid, action=action or ACTION_LOGGED,
        )

    def describe(self) -> str:
        """One-line console representation."""
        src = f"{self.src_ip}:{self.src_port}" if self.src_port is not None else str(self.src_ip)
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port is not None else str(self.dst_ip)
        sid = f" [sid:{self.sid}]" if self.sid else ""
        return f"{self.time_iso()} [{SEVERITY_NAMES.get(self.severity, '?').upper():8s}] " \
               f"{self.category:16s} {self.name}{sid}  {src} -> {dst} ({self.protocol})"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.describe()
