"""Detector base class and shared helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from nids.alert import Alert


class BaseDetector:
    """Common plumbing for behavioural detectors.

    Subclasses set ``config_key`` (mapping into ``detectors:`` of the YAML
    config) and ``name``, then implement :meth:`process`, returning zero or
    more alerts per packet.  Detectors are stateful across packets.
    """

    config_key = "base"
    name = "base"
    category = "Anomaly"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detector_cfg: Dict[str, Any] = (
            config.get("detectors", {}).get(self.config_key, {}))
        self.enabled: bool = bool(self.detector_cfg.get("enabled", True))
        self.alerts_emitted = 0

    def process(self, meta) -> List[Alert]:
        """Inspect one normalized packet; return alerts (possibly empty)."""
        return []

    # ------------------------------------------------------------------

    def make_alert(
        self,
        msg: str,
        severity: int,
        meta,
        details: str = "",
        category: Optional[str] = None,
        sid: Optional[int] = None,
    ) -> Alert:
        self.alerts_emitted += 1
        return Alert(
            timestamp=meta.timestamp,
            name=msg,
            category=category or self.category,
            severity=severity,
            detector=self.name,
            protocol=meta.protocol,
            src_ip=meta.src_ip,
            src_port=meta.src_port,
            dst_ip=meta.dst_ip,
            dst_port=meta.dst_port,
            details=details,
            sid=sid,
        )
