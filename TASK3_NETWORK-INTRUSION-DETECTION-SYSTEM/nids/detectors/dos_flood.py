"""Volume/flood based denial-of-service detection."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

from nids.alert import Alert, CAT_DOS
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta


class DoSDetector(BaseDetector):
    """Rate-based flood detection: SYN, UDP, ICMP and HTTP floods.

    Every flood type keeps a rolling per-key window (timestamps).  When the
    count inside the window crosses the configured threshold an alert fires,
    subject to a per-source cooldown.  SYN floods with many distinct sources
    are reported as distributed (DDoS) at severity 4.
    """

    config_key = "dos"
    name = "dos"
    category = CAT_DOS

    def __init__(self, config):
        super().__init__(config)
        cfg = self.detector_cfg
        syn = cfg.get("syn_flood", {})
        udp = cfg.get("udp_flood", {})
        icmp = cfg.get("icmp_flood", {})
        http = cfg.get("http_flood", {})
        self.syn_window = float(syn.get("window_seconds", 10))
        self.syn_threshold = int(syn.get("packet_threshold", 100))
        self.udp_window = float(udp.get("window_seconds", 10))
        self.udp_threshold = int(udp.get("packet_threshold", 200))
        self.icmp_window = float(icmp.get("window_seconds", 10))
        self.icmp_threshold = int(icmp.get("packet_threshold", 60))
        self.http_window = float(http.get("window_seconds", 10))
        self.http_threshold = int(http.get("packet_threshold", 120))
        self.cooldown = float(cfg.get("cooldown_seconds", 60))

        self._syn: Dict[Tuple[str, int], Deque[Tuple[float, str]]] = defaultdict(deque)
        self._udp: Dict[str, Deque[float]] = defaultdict(deque)
        self._icmp: Dict[str, Deque[float]] = defaultdict(deque)
        self._http: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        if meta.protocol == "TCP" and meta.is_tcp_syn and meta.dst_ip is not None:
            return self._check_syn(meta)
        if meta.protocol == "UDP" and meta.src_ip is not None:
            return self._check_volume(self._udp, meta, self.udp_window,
                                      self.udp_threshold, "UDP", "udp")
        if meta.protocol == "ICMP" and meta.src_ip is not None and meta.icmp_type == 8:
            return self._check_volume(self._icmp, meta, self.icmp_window,
                                      self.icmp_threshold, "ICMP echo", "icmp")
        if (meta.http and meta.http.get("is_request")
                and meta.http.get("method") == "GET" and meta.src_ip is not None):
            return self._check_volume(self._http, meta, self.http_window,
                                      self.http_threshold, "HTTP GET", "http")
        return []

    # ------------------------------------------------------------------

    def _check_syn(self, meta: PacketMeta) -> List[Alert]:
        key = (meta.dst_ip, meta.dst_port or 0)
        window = self._syn[key]
        window.append((meta.timestamp, meta.src_ip or "?"))
        cutoff = meta.timestamp - self.syn_window
        while window and window[0][0] < cutoff:
            window.popleft()
        if len(window) < self.syn_threshold:
            return []
        if meta.timestamp - self._last_alert.get(f"syn:{meta.dst_ip}", 0.0) < self.cooldown:
            return []
        self._last_alert[f"syn:{meta.dst_ip}"] = meta.timestamp
        unique_sources: Set[str] = {src for _, src in window}
        distributed = len(unique_sources) >= 5
        name = ("DDOS: distributed SYN flood against " if distributed
                else "DOS: TCP SYN flood against ")
        name += f"{meta.dst_ip}:{meta.dst_port}"
        return [self.make_alert(
            msg=name,
            severity=4 if distributed else 3,
            meta=meta,
            details=(f"{len(window)} SYN packets in {self.syn_window:.0f}s from "
                     f"{len(unique_sources)} unique source(s)"),
            category=CAT_DOS,
        )]

    def _check_volume(self, store: Dict[str, Deque[float]], meta: PacketMeta,
                      window_s: float, threshold: int, label: str,
                      kind: str) -> List[Alert]:
        key = meta.src_ip
        window = store[key]
        window.append(meta.timestamp)
        cutoff = meta.timestamp - window_s
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) < threshold:
            return []
        if meta.timestamp - self._last_alert.get(kind, 0.0) < self.cooldown:
            return []
        self._last_alert[kind] = meta.timestamp
        return [self.make_alert(
            msg=f"DOS: {label} flood from {meta.src_ip}",
            severity=3,
            meta=meta,
            details=(f"{len(window)} {label} packets in {window_s:.0f}s "
                     f"(threshold {threshold})"),
            category=CAT_DOS,
        )]
