"""DNS tunnelling / exfiltration-over-DNS detection."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from nids.alert import Alert, CAT_EXFIL
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta
from nids.utils import shannon_entropy

_HEX_LABEL = re.compile(r"^[a-f0-9]{24,}$")
_B32_LABEL = re.compile(r"^[a-z2-7]{24,}$")


class DNSTunnelDetector(BaseDetector):
    """Flags DNS queries that look like tunnelling / exfiltration channels.

    Heuristics (per query):
      * an unusually long hostname or single label
      * a long high-entropy label (random-looking, e.g. encoded payloads)
      * base16/base32-encoded-looking labels of significant length
    plus a rate heuristic: a host issuing an abnormal number of queries.
    """

    config_key = "dns_tunnel"
    name = "dns_tunnel"
    category = CAT_EXFIL

    def __init__(self, config):
        super().__init__(config)
        cfg = self.detector_cfg
        self.max_label = int(cfg.get("max_label_length", 45))
        self.max_name = int(cfg.get("max_name_length", 120))
        self.entropy_threshold = float(cfg.get("entropy_threshold", 3.5))
        self.min_entropy_len = int(cfg.get("min_entropy_label_length", 20))
        self.rate_window = float(cfg.get("query_rate_window", 60))
        self.rate_threshold = int(cfg.get("query_rate_threshold", 40))
        self.cooldown = float(cfg.get("cooldown_seconds", 60))
        self._query_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        if meta.protocol != "DNS" or meta.dns_is_response or not meta.dns_qname:
            return []
        qname = meta.dns_qname.rstrip(".")
        src = meta.src_ip or "_unknown"
        alerts: List[Alert] = []

        # rate heuristic
        window = self._query_times[src]
        window.append(meta.timestamp)
        cutoff = meta.timestamp - self.rate_window
        while window and window[0] < cutoff:
            window.popleft()
        if (len(window) >= self.rate_threshold
                and meta.timestamp - self._last_alert.get(f"rate:{src}", -float("inf")) >= self.cooldown):
            self._last_alert[f"rate:{src}"] = meta.timestamp
            alerts.append(self.make_alert(
                msg=f"EXFIL: abnormal DNS query rate from {meta.src_ip or '?'}",
                severity=3,
                meta=meta,
                details=(f"{len(window)} DNS queries in {self.rate_window:.0f}s "
                         f"(threshold {self.rate_threshold})"),
                category=CAT_EXFIL,
            ))

        # per-query shape heuristics (cooldown suppressed => None)
        labels = qname.split(".")
        if len(qname) > self.max_name:
            alerts.append(self._shape_alert(meta, "oversized hostname",
                                            f"query name length {len(qname)} > {self.max_name}"))
        else:
            for label in labels:
                if len(label) > self.max_label:
                    alerts.append(self._shape_alert(
                        meta, "oversized DNS label",
                        f"label '{label[:48]}' length {len(label)} > {self.max_label}"))
                    break
                if len(label) >= self.min_entropy_len:
                    entropy = shannon_entropy(label.lower())
                    if entropy >= self.entropy_threshold or _HEX_LABEL.match(label.lower()) \
                            or _B32_LABEL.match(label.lower()):
                        alerts.append(self._shape_alert(
                            meta, "high-entropy encoded label",
                            f"label '{label[:48]}' entropy {entropy:.2f} "
                            f">= {self.entropy_threshold}"))
                        break

        return [a for a in alerts if a is not None][:2]  # cap alerts per packet

    # ------------------------------------------------------------------

    def _shape_alert(self, meta: PacketMeta, finding: str, detail: str) -> Optional[Alert]:
        src = meta.src_ip or "_unknown"
        cooldown_key = f"shape:{src}"
        last = self._last_alert.get(cooldown_key, -float("inf"))
        if meta.timestamp - last < self.cooldown:
            return None
        self._last_alert[cooldown_key] = meta.timestamp
        return self.make_alert(
            msg=f"EXFIL: DNS tunnelling suspected ({finding})",
            severity=2,
            meta=meta,
            details=f"query '{meta.dns_qname}' - {detail}",
            category=CAT_EXFIL,
        )
