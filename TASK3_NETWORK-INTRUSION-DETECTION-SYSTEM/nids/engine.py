"""The NIDS orchestrator: capture -> detection -> response -> persistence."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from nids.alert import Alert, ACTION_LOGGED
from nids.alert_store import AlertStore
from nids.detectors import DETECTOR_CLASSES
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta
from nids.response import ResponseEngine
from nids.rule_engine import RuleEngine

logger = logging.getLogger("nids.engine")


class NidsEngine:
    """Feeds packets through all detectors and the signature rule engine."""

    def __init__(self, config: Dict[str, Any], on_alert: Optional[Callable[[Alert], None]] = None,
                 store: Optional[AlertStore] = None):
        self.config = config
        self.on_alert = on_alert
        self.store = store or AlertStore(config["general"]["db_path"])

        self.rule_engine = RuleEngine(config)
        if self.rule_engine.enabled:
            self.rule_engine.load_rules()
        self.detectors: List[BaseDetector] = [cls(config) for cls in DETECTOR_CLASSES]

        self.response = ResponseEngine(config, self.store)

        jsonl_path = config["general"].get("alerts_jsonl")
        self._jsonl_path = Path(jsonl_path) if jsonl_path else None
        self._jsonl_lock = threading.Lock()

        # statistics
        self.start_ts: Optional[float] = None
        self.packets_processed = 0
        self.alerts_generated = 0
        self.alerts_by_detector: Dict[str, int] = {}
        self.alerts_by_severity: Dict[int, int] = {}

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    def process_packet(self, pkt) -> List[Alert]:
        """Accept a raw scapy packet (used by tests and live capture)."""
        from nids.packet_capture import normalize
        meta = normalize(pkt)
        return self.process_meta(meta) if meta else []

    def process_meta(self, meta: PacketMeta) -> List[Alert]:
        """Run one normalized packet through every detector + rules."""
        if self.start_ts is None:
            self.start_ts = time.time()
        self.packets_processed += 1

        alerts: List[Alert] = []
        for detector in self.detectors:
            if detector.enabled:
                try:
                    alerts.extend(detector.process(meta))
                except Exception:  # a broken detector must not stop the engine
                    logger.exception("Detector %s failed", detector.name)
        try:
            alerts.extend(self.rule_engine.match_packet(meta))
        except Exception:
            logger.exception("Rule engine failed on packet")

        for alert in alerts:
            alert.action = ACTION_LOGGED
            self.store.save_alert(alert)
            self.response.handle(alert)
            self._write_jsonl(alert)
            self.alerts_generated += 1
            self.alerts_by_detector[alert.detector] = (
                self.alerts_by_detector.get(alert.detector, 0) + 1)
            self.alerts_by_severity[alert.severity] = (
                self.alerts_by_severity.get(alert.severity, 0) + 1)
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:
                    logger.exception("on_alert callback failed")
        return alerts

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def run_pcap(self, path: str, verbose: bool = False) -> Dict[str, Any]:
        """Batch-process a pcap file (fast, offline)."""
        from nids.packet_capture import iter_pcap
        count = 0
        for meta in iter_pcap(path):
            alerts = self.process_meta(meta)
            if verbose:
                for alert in alerts:
                    self._print_alert(alert)
            count += 1
            if count % 2000 == 0:
                logger.info("... %d packets processed", count)
        self.response.maintenance()
        return self.summary(source=f"pcap:{path}")

    def run_replay(self, path: str, speed: float = 10.0,
                   stop_event: Optional[threading.Event] = None,
                   heartbeat: bool = True) -> Dict[str, Any]:
        """Replay a pcap paced in real time with live console alerts."""
        from nids.packet_capture import iter_replay
        hb_thread = self._start_heartbeat(stop_event) if heartbeat else None
        for meta in iter_replay(path, speed=speed,
                                stop_check=stop_event.is_set if stop_event else None):
            for alert in self.process_meta(meta):
                self._print_alert(alert)
        if hb_thread:
            self._stop_heartbeat.set()
            hb_thread.join(timeout=2)
        self.response.maintenance()
        return self.summary(source=f"replay:{path}@{speed}x")

    def run_live(self, interface: str, bpf_filter: str = "", promisc: bool = True,
                 stop_event: Optional[threading.Event] = None,
                 stats_interval: float = 30.0) -> Dict[str, Any]:
        """Continuous monitoring on a live interface. Ctrl-C to stop."""
        from nids.packet_capture import iter_live
        stop_event = stop_event or threading.Event()
        hb_thread = self._start_heartbeat(stop_event, interface)
        last_stats = time.time()
        try:
            for meta in iter_live(interface, bpf_filter=bpf_filter, promisc=promisc,
                                  stop_check=stop_event.is_set):
                for alert in self.process_meta(meta):
                    self._print_alert(alert)
                if time.time() - last_stats >= stats_interval:
                    self._log_progress(interface)
                    self.response.maintenance()
                    last_stats = time.time()
        except KeyboardInterrupt:
            logger.info("Interrupted by user - shutting down capture")
        finally:
            self._stop_heartbeat.set()
            hb_thread.join(timeout=2)
        return self.summary(source=f"live:{interface}")

    # ------------------------------------------------------------------
    # Console output / heartbeat / stats
    # ------------------------------------------------------------------

    @staticmethod
    def _print_alert(alert: Alert) -> None:
        from nids.utils import paint, severity_paint, BRIGHT_RED, BOLD, DIM
        prefix = " !! BLOCKED" if alert.action == "blocked" else ""
        line = severity_paint(alert.severity, alert.describe())
        if alert.action == "blocked":
            line += paint(prefix, BRIGHT_RED + BOLD)
        print(line, flush=True)

    def _start_heartbeat(self, stop_event: Optional[threading.Event],
                         source: str = "") -> threading.Thread:
        self._stop_heartbeat = threading.Event()

        def _beat():
            while not self._stop_heartbeat.wait(5):
                self.store.heartbeat(f"{self.packets_processed} pkts|{source}")
                self.response.maintenance()

        thread = threading.Thread(target=_beat, name="nids-heartbeat", daemon=True)
        thread.start()
        return thread

    def _log_progress(self, interface: str) -> None:
        logger.info("monitoring %s: %d packets, %d alerts (crit=%d high=%d)",
                    interface, self.packets_processed, self.alerts_generated,
                    self.alerts_by_severity.get(4, 0), self.alerts_by_severity.get(3, 0))

    def summary(self, source: str = "") -> Dict[str, Any]:
        elapsed = (time.time() - self.start_ts) if self.start_ts else 0.0
        return {
            "source": source,
            "packets": self.packets_processed,
            "alerts": self.alerts_generated,
            "elapsed_seconds": round(elapsed, 2),
            "by_detector": dict(self.alerts_by_detector),
            "by_severity": {str(k): v for k, v in sorted(self.alerts_by_severity.items())},
            "blocks": self.response.stats,
        }

    # ------------------------------------------------------------------

    def _write_jsonl(self, alert: Alert) -> None:
        if self._jsonl_path is None:
            return
        try:
            with self._jsonl_lock:
                self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
                with self._jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(alert.to_dict()) + "\n")
        except OSError as exc:
            logger.debug("JSONL write failed: %s", exc)
