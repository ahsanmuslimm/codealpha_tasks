"""Credential brute-force detection for SSH/RDP/FTP and web logins."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from nids.alert import Alert, CAT_BRUTE_FORCE
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC",
}


class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts to authentication services.

    Two complementary heuristics:

    1. bursts of TCP SYNs to well-known auth ports from a single source
    2. bursts of HTTP 401/403 responses served to a single client
       (works on full-duplex captures, e.g. pcaps or mirrored traffic)
    """

    config_key = "brute_force"
    name = "brute_force"
    category = CAT_BRUTE_FORCE

    def __init__(self, config):
        super().__init__(config)
        cfg = self.detector_cfg
        self.window = float(cfg.get("window_seconds", 60))
        self.threshold = int(cfg.get("attempt_threshold", 8))
        self.cooldown = float(cfg.get("cooldown_seconds", 60))
        self.auth_ports = set(int(p) for p in cfg.get("auth_ports", SERVICE_NAMES))
        self.http_failure_codes = set(int(c) for c in cfg.get("http_failure_codes", [401, 403]))
        self.http_threshold = int(cfg.get("http_failure_threshold", 10))
        # (src_ip, port) -> deque[timestamps]  for TCP attempts
        self._attempts: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        # client_ip -> deque[timestamps of auth failures]
        self._http_failures: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        if meta.protocol == "TCP":
            if meta.is_tcp_syn and meta.dst_port in self.auth_ports:
                return self._record_attempt(meta)
        if meta.http and not meta.http.get("is_request"):
            status = meta.http.get("status") or 0
            if status in self.http_failure_codes:
                return self._record_http_failure(meta)
        return []

    # ------------------------------------------------------------------

    def _record_attempt(self, meta: PacketMeta) -> List[Alert]:
        key = (meta.src_ip, meta.dst_port)
        window = self._attempts[key]
        window.append(meta.timestamp)
        self._prune(window, meta.timestamp)
        if len(window) < self.threshold:
            return []
        cooldown_key = ("tcp", meta.src_ip)
        if meta.timestamp - self._last_alert.get(cooldown_key, 0.0) < self.cooldown:
            return []
        self._last_alert[cooldown_key] = meta.timestamp
        service = SERVICE_NAMES.get(meta.dst_port, f"port {meta.dst_port}")
        return [self.make_alert(
            msg=f"BRUTE FORCE: {service} authentication attempts from {meta.src_ip}",
            severity=3,
            meta=meta,
            details=(f"{len(window)} connection attempts to {service} "
                     f"({meta.dst_ip}:{meta.dst_port}) within {self.window:.0f}s"),
            category=CAT_BRUTE_FORCE,
        )]

    def _record_http_failure(self, meta: PacketMeta) -> List[Alert]:
        client = meta.dst_ip  # responses travel server -> client
        if client is None:
            return []
        window = self._http_failures[client]
        window.append(meta.timestamp)
        self._prune(window, meta.timestamp)
        if len(window) < self.http_threshold:
            return []
        cooldown_key = ("http", client)
        if meta.timestamp - self._last_alert.get(cooldown_key, 0.0) < self.cooldown:
            return []
        self._last_alert[cooldown_key] = meta.timestamp
        return [self.make_alert(
            msg=f"BRUTE FORCE: repeated HTTP auth failures against {client}",
            severity=2,
            meta=meta,
            details=(f"{len(window)} HTTP {sorted(self.http_failure_codes)} responses "
                     f"served to {client} within {self.window:.0f}s"),
            category=CAT_BRUTE_FORCE,
        )]

    # ------------------------------------------------------------------

    def _prune(self, window: Deque[float], now: float) -> None:
        cutoff = now - self.window
        while window and window[0] < cutoff:
            window.popleft()
