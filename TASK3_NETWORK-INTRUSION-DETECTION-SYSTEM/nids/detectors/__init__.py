"""Behavioural detector registry."""

from __future__ import annotations

from typing import Dict, List, Type

from nids.detectors.arp_spoof import ARPSpoofDetector
from nids.detectors.base import BaseDetector
from nids.detectors.brute_force import BruteForceDetector
from nids.detectors.dns_tunnel import DNSTunnelDetector
from nids.detectors.dos_flood import DoSDetector
from nids.detectors.port_scan import PortScanDetector
from nids.detectors.web_attack import WebAttackDetector

DETECTOR_CLASSES: List[Type[BaseDetector]] = [
    PortScanDetector,
    BruteForceDetector,
    DoSDetector,
    ARPSpoofDetector,
    DNSTunnelDetector,
    WebAttackDetector,
]

__all__ = [
    "BaseDetector",
    "DETECTOR_CLASSES",
    "PortScanDetector",
    "BruteForceDetector",
    "DoSDetector",
    "ARPSpoofDetector",
    "DNSTunnelDetector",
    "WebAttackDetector",
]
