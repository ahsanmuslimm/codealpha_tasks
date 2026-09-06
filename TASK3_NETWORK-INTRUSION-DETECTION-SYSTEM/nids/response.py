"""Automated incident response: blocking, escalation and notifications.

Response policy (config ``response:``):

* immediate  - alerts at/above ``immediate_severity`` (default 4) block the
  source IP right away
* escalation - ``escalate_count`` alerts at/above ``escalate_min_severity``
  inside ``escalate_window_minutes`` block the source
* whitelist  - IPs in ``general.whitelist_ips`` are never touched by *active*
  enforcement (so you can never lock yourself out); with
  ``whitelist_governs_active_only`` the demo-safe *simulate* mode still
  records blocks for whitelisted IPs so the workflow stays demonstrable

Modes:
  simulate - blocks are recorded in the block table + logs, no firewall change
  active   - adds a real firewall rule (Windows: netsh advfirewall,
             Linux: iptables), then records the block

Every executed block can be mirrored to a webhook and/or e-mail.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from nids.alert import Alert, ACTION_BLOCKED, ACTION_LOGGED
from nids.alert_store import AlertStore

logger = logging.getLogger("nids.response")


class ResponseEngine:
    """Decides and executes response actions for alerts."""

    def __init__(self, config: Dict[str, Any], store: AlertStore):
        self.config = config
        self.store = store
        cfg = config.get("response", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.mode = str(cfg.get("mode", "simulate")).lower()
        if self.mode not in ("simulate", "active"):
            logger.warning("Unknown response mode %r - falling back to simulate", self.mode)
            self.mode = "simulate"
        self.ttl_seconds = int(float(cfg.get("block_ttl_minutes", 30)) * 60)
        self.immediate_severity = int(cfg.get("immediate_severity", 4))
        self.escalate_min_severity = int(cfg.get("escalate_min_severity", 3))
        self.escalate_count = int(cfg.get("escalate_count", 4))
        self.escalate_window = float(cfg.get("escalate_window_minutes", 5)) * 60
        self.whitelist_governs_active_only = bool(cfg.get("whitelist_governs_active_only", True))
        self.whitelist = set(config.get("general", {}).get("whitelist_ips", []))

        notifications = cfg.get("notifications", {}) or {}
        self.webhook_url = notifications.get("webhook_url", "")
        self.email_cfg = notifications.get("email", {}) or {}

        self._recent_alerts: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._lock = threading.RLock()
        self.stats = {"blocks_executed": 0, "blocks_simulated": 0, "notifications_sent": 0}

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def handle(self, alert: Alert) -> None:
        """Evaluate one alert and act on it if policy says so."""
        if not self.enabled or not alert.src_ip:
            return
        should_block, reason = self._decide(alert)
        if not should_block:
            return
        self._execute_block(alert.src_ip, reason, alert)

    def _decide(self, alert: Alert) -> Tuple[bool, str]:
        now = alert.timestamp
        ring = self._recent_alerts[alert.src_ip]
        ring.append((now, alert.severity))
        cutoff = now - self.escalate_window
        while ring and ring[0][0] < cutoff:
            ring.popleft()

        if alert.severity >= self.immediate_severity:
            return True, (f"immediate response: severity {alert.severity} alert "
                          f"'{alert.name}'")
        if alert.severity >= self.escalate_min_severity:
            escalating = [s for _, s in ring if s >= self.escalate_min_severity]
            if len(escalating) >= self.escalate_count:
                return True, (f"escalation: {len(escalating)} alerts with severity >= "
                              f"{self.escalate_min_severity} within "
                              f"{self.escalate_window / 60:.0f} min")
        return False, ""

    # ------------------------------------------------------------------
    # Block execution
    # ------------------------------------------------------------------

    def _execute_block(self, ip: str, reason: str, alert: Optional[Alert] = None) -> None:
        is_whitelisted = ip in self.whitelist
        mode = self.mode
        if is_whitelisted and not self.whitelist_governs_active_only:
            logger.info("Response suppressed for whitelisted IP %s (%s)", ip, reason)
            return
        if is_whitelisted and mode == "active":
            # Never risk cutting off the analyst: degrade to a recorded block.
            logger.warning("IP %s is whitelisted - downgrading active block to "
                           "a recorded (simulate) block", ip)
            mode = "simulate"

        if mode == "active":
            ok = self._firewall_block(ip)
            suffix = "" if ok else " (firewall command failed - recorded only)"
        else:
            ok = None
            suffix = " (simulated)"

        created = self.store.save_block(
            ip, reason=f"{reason}{suffix}", mode=mode, ttl_seconds=self.ttl_seconds)
        if alert is not None:
            alert.action = ACTION_BLOCKED
        if created:
            if mode == "active":
                self.stats["blocks_executed"] += 1
            else:
                self.stats["blocks_simulated"] += 1
            self._notify(alert, ip, reason, mode)
            logger.warning("[RESPONSE] %s block applied to %s - %s", mode.upper(), ip, reason)

    # -- firewall adapters ------------------------------------------------

    def _firewall_block(self, ip: str) -> bool:
        try:
            system = platform.system()
            if system == "Windows":
                rule = f"NIDS_BLOCK_{ip.replace('.', '_').replace(':', '_')}"
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={rule}", "dir=in", "action=block", f"remoteip={ip}"]
            elif system == "Linux":
                cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            elif system == "Darwin":
                # pf requires a table update; keep it simple and documented
                logger.error("Active blocking on macOS requires pf configuration - "
                             "see docs/RESPONSE_PLAYBOOK.md")
                return False
            else:
                logger.error("No firewall adapter for %s", system)
                return False
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                    check=False)
            if result.returncode == 0:
                logger.info("Firewall block applied to %s via %s", ip, system)
                return True
            logger.error("Firewall command failed (%s): %s", result.returncode,
                         (result.stderr or result.stdout).strip()[:200])
            return False
        except (OSError, subprocess.SubprocessError) as exc:
            logger.error("Firewall block for %s raised: %s", ip, exc)
            return False

    def _firewall_unblock(self, ip: str) -> bool:
        try:
            system = platform.system()
            if system == "Windows":
                rule = f"NIDS_BLOCK_{ip.replace('.', '_').replace(':', '_')}"
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
            elif system == "Linux":
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            else:
                return False
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                    check=False)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError) as exc:
            logger.error("Firewall unblock for %s raised: %s", ip, exc)
            return False

    # ------------------------------------------------------------------
    # Manual actions (dashboard / CLI)
    # ------------------------------------------------------------------

    def manual_block(self, ip: str, reason: str = "manual block from dashboard") -> Tuple[bool, str]:
        """Operator-initiated block; honours the whitelist for active mode."""
        mode = self.mode
        if ip in self.whitelist and mode == "active":
            mode = "simulate"
            reason += " (whitelisted - recorded only)"
        created = self.store.save_block(ip, reason=reason, mode=mode,
                                        ttl_seconds=self.ttl_seconds)
        if mode == "active" and ip not in self.whitelist:
            self._firewall_block(ip)
        if created:
            self._notify(None, ip, reason, mode)
        return created, mode

    def manual_unblock(self, ip: str) -> bool:
        lifted = self.store.lift_block(ip)
        if self.mode == "active":
            self._firewall_unblock(ip)
        return lifted

    # ------------------------------------------------------------------
    # Maintenance + notifications
    # ------------------------------------------------------------------

    def maintenance(self) -> None:
        """Expire old blocks; call periodically from the engine loop."""
        self.store.expire_old_blocks()

    def _notify(self, alert: Optional[Alert], ip: str, reason: str, mode: str) -> None:
        payload = {
            "event": "nids_block",
            "ip": ip,
            "mode": mode,
            "reason": reason,
            "timestamp": time.time(),
        }
        if alert is not None:
            payload["alert"] = alert.to_dict()
        if self.webhook_url:
            try:
                import requests
                requests.post(self.webhook_url, json=payload, timeout=5)
                self.stats["notifications_sent"] += 1
                logger.info("Webhook notification sent for block of %s", ip)
            except Exception as exc:  # network errors must never break detection
                logger.error("Webhook notification failed: %s", exc)
        if self.email_cfg.get("enabled"):
            self._send_email(ip, reason)

    def _send_email(self, ip: str, reason: str) -> None:
        try:
            import smtplib
            from email.mime.text import MIMEText
            cfg = self.email_cfg
            msg = MIMEText(f"NIDS blocked {ip}.\n\nReason: {reason}\n"
                           f"Mode: {self.mode}\nTime: {time.ctime()}")
            msg["Subject"] = f"[NIDS] Source IP {ip} blocked"
            msg["From"] = cfg.get("from_addr", "nids@localhost")
            msg["To"] = ", ".join(cfg.get("to_addrs", [])) or cfg.get("from_addr", "nids@localhost")
            with smtplib.SMTP(cfg.get("smtp_host", "localhost"),
                              int(cfg.get("smtp_port", 25)), timeout=10) as smtp:
                smtp.sendmail(msg["From"], cfg.get("to_addrs") or [msg["From"]],
                              msg.as_string())
            self.stats["notifications_sent"] += 1
            logger.info("E-mail notification sent for block of %s", ip)
        except Exception as exc:
            logger.error("E-mail notification failed: %s", exc)
