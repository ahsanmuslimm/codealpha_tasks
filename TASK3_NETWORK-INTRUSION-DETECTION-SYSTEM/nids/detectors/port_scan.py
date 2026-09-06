"""TCP/UDP port-scan and host-sweep detection (SYN, stealth and UDP probes)."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Tuple

from nids.alert import Alert, CAT_RECON
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta
from nids.utils import SlidingWindow


class PortScanDetector(BaseDetector):
    """Alerts when a source probes many distinct ports (or hosts) in a window.

    Covers: TCP SYN scans, FIN/NULL/XMAS stealth scans, and UDP probes to
    distinct ports.  A per-source cooldown keeps the alert volume sane.
    """

    config_key = "port_scan"
    name = "port_scan"
    category = CAT_RECON

    def __init__(self, config):
        super().__init__(config)
        cfg = self.detector_cfg
        self.window = float(cfg.get("window_seconds", 30))
        self.threshold = int(cfg.get("distinct_ports", 12))
        self.cooldown = float(cfg.get("cooldown_seconds", 45))
        # src_ip -> {"syn": {targets}, "stealth": ..., "udp": ...}
        self._probes: Dict[str, Dict[str, set]] = defaultdict(
            lambda: {"syn": set(), "stealth": set(), "udp": set()})
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        if meta.src_ip is None:
            return []
        kind = self._classify_probe(meta)
        if kind is None:
            return []
        entry = self._probes[meta.src_ip][kind]
        entry.add((meta.dst_ip, meta.dst_port, meta.timestamp))
        self._prune(entry, meta.timestamp)
        if len(entry) < self.threshold:
            return []
        last = self._last_alert.get(meta.src_ip, 0.0)
        if meta.timestamp - last < self.cooldown:
            return []
        self._last_alert[meta.src_ip] = meta.timestamp
        return [self._build_alert(meta, kind, entry)]

    # ------------------------------------------------------------------

    @staticmethod
    def _classify_probe(meta: PacketMeta) -> str | None:
        if meta.protocol == "TCP":
            if meta.is_tcp_syn:
                return "syn"
            # stealth: FIN / NULL / XMAS (no SYN, no ACK, no payload)
            if ("A" not in meta.tcp_flags and "S" not in meta.tcp_flags
                    and not meta.payload):
                return "stealth"
        elif meta.protocol == "UDP" and not meta.payload:
            return "udp"
        return None

    def _prune(self, entry: set, now: float) -> None:
        cutoff = now - self.window
        entry.intersection_update({t for t in entry if t[2] >= cutoff})

    def _build_alert(self, meta: PacketMeta, kind: str, entry: set) -> Alert:
        ports = {(dst_ip, port) for dst_ip, port, _ in entry}
        hosts = {dst_ip for dst_ip, _ in ports}
        scan_type = {
            "syn": "TCP SYN scan",
            "stealth": "stealth scan (FIN/NULL/XMAS)",
            "udp": "UDP scan",
        }[kind]
        if len(hosts) > 10:
            scan_type += " (horizontal host sweep)"
        elif len(ports) > self.threshold * 3:
            scan_type += " (aggressive/full-range)"
        sample_ports = sorted({p for _, p in ports})[:12]
        details = (f"{len(ports)} distinct ports probed on {len(hosts)} host(s) "
                   f"within {self.window:.0f}s; sample ports: {sample_ports}")
        severity = 3 if len(ports) >= self.threshold * 3 else 2
        return self.make_alert(
            msg=f"PORT SCAN: {scan_type}",
            severity=severity,
            meta=meta,
            details=details,
            category=CAT_RECON,
        )
