"""ARP spoofing / man-in-the-middle detection."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from nids.alert import Alert, CAT_MITM
from nids.detectors.base import BaseDetector
from nids.packets import PacketMeta

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


class ARPSpoofDetector(BaseDetector):
    """Tracks IP->MAC bindings learned from ARP replies and alerts on conflicts.

    An IP that starts answering from a different MAC address is the classic
    ARP-spoofing / MITM pattern (attacker poisons the victim's ARP cache by
    claiming the gateway's IP).  Bindings for configured gateway IPs are
    treated as especially sensitive.
    """

    config_key = "arp_spoof"
    name = "arp_spoof"
    category = CAT_MITM

    def __init__(self, config):
        super().__init__(config)
        self.cooldown = float(self.detector_cfg.get("cooldown_seconds", 60))
        self.gateways = set(self.detector_cfg.get("gateways", []))
        self._bindings: Dict[str, str] = {}
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def process(self, meta: PacketMeta) -> List[Alert]:
        if meta.protocol != "ARP" or meta.arp_op != 2:  # replies (is-at) only
            return []
        ip = meta.arp_sender_ip
        mac = (meta.arp_sender_mac or "").lower()
        if not ip or not mac or mac in (BROADCAST_MAC, ZERO_MAC):
            return []

        known = self._bindings.get(ip)
        if known is None:
            self._bindings[ip] = mac
            return []
        if known == mac:
            return []

        # conflict learned before; re-learn silently after an alert cooldown
        last = self._last_alert.get(ip, 0.0)
        if meta.timestamp - last < self.cooldown:
            return []
        self._last_alert[ip] = meta.timestamp
        self._bindings[ip] = mac
        return [self._build_alert(meta, ip, known, mac)]

    # ------------------------------------------------------------------

    def _build_alert(self, meta: PacketMeta, ip: str, old_mac: str, new_mac: str) -> Alert:
        is_gateway = ip in self.gateways
        name = ("ARP SPOOFING: gateway IP hijacked"
                if is_gateway else "ARP SPOOFING: IP-MAC conflict detected")
        details = (f"{ip} was bound to {old_mac} and now answers from {new_mac}"
                   + (" - possible man-in-the-middle attack against the gateway" if is_gateway else ""))
        return self.make_alert(
            msg=name,
            severity=4 if is_gateway else 3,
            meta=meta,
            details=details,
            category=CAT_MITM,
        )
