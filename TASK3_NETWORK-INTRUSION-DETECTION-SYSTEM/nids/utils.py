"""Shared low-level helpers: logging, ANSI colours, IP math, sliding windows."""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import sys
import time
from collections import deque
from typing import Iterable, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

_ANSI_ENABLED = False

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GREY = "\033[90m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_CYAN = "\033[96m"


def enable_ansi() -> None:
    """Enable ANSI escape sequences on Windows 10+ terminals."""
    global _ANSI_ENABLED
    if _ANSI_ENABLED:
        return
    if os.name == "nt":
        os.system("")  # enables VT processing in cmd / Windows Terminal
    _ANSI_ENABLED = True


def paint(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI codes (no-op when colour is unavailable)."""
    if not _ANSI_ENABLED:
        enable_ansi()
    if not sys.stdout.isatty() and os.environ.get("FORCE_COLOR") is None:
        return str(text)
    return "".join(codes) + str(text) + RESET


def severity_paint(severity: int, text: str) -> str:
    colours = {4: BRIGHT_RED + BOLD, 3: BRIGHT_YELLOW, 2: CYAN, 1: GREY}
    return paint(text, colours.get(severity, WHITE))


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def ts_to_iso(ts: float) -> str:
    """Unix timestamp -> ``YYYY-MM-DD HH:MM:SS`` (local time, no re-import cost)."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def now_ts() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except (ValueError, AttributeError):
        return False


def parse_networks(specs: Optional[Iterable[str]]) -> List[ipaddress._BaseNetwork]:
    """Parse a list of CIDR/host strings, ignoring invalid entries."""
    nets: List[ipaddress._BaseNetwork] = []
    if not specs:
        return nets
    for spec in specs:
        try:
            nets.append(ipaddress.ip_network(str(spec).strip(), strict=False))
        except ValueError:
            logging.getLogger("nids.utils").warning("Invalid network spec ignored: %r", spec)
    return nets


def ip_in_nets(ip: Optional[str], nets: Sequence[ipaddress._BaseNetwork]) -> bool:
    """True when *ip* falls inside any of *nets* (empty list = no match)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Maths / misc
# ---------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """Shannon entropy of *value* in bits per character (0.0 for empty input)."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:,.1f} {unit}"
        num /= 1024.0
    return f"{num:,.1f} PB"


class SlidingWindow:
    """Timestamp ring-buffer supporting O(1) counts inside a rolling window."""

    __slots__ = ("window", "_events")

    def __init__(self, window: float):
        self.window = float(window)
        self._events: deque = deque()

    def add(self, ts: Optional[float] = None) -> None:
        ts = now_ts() if ts is None else ts
        self._events.append(ts)

    def prune(self, now: Optional[float] = None) -> None:
        now = now_ts() if now is None else now
        cutoff = now - self.window
        events = self._events
        while events and events[0] < cutoff:
            events.popleft()

    def count(self, now: Optional[float] = None) -> int:
        self.prune(now)
        return len(self._events)

    def events(self) -> List[float]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()
