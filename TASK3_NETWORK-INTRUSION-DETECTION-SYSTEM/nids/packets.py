"""Protocol-agnostic packet model shared by capture, detectors and rules.

``PacketMeta`` is a plain dataclass so detectors and unit tests never need
scapy directly.  ``packet_capture.normalize`` converts raw scapy packets into
this representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Protocol labels used across the engine
P_TCP = "TCP"
P_UDP = "UDP"
P_ICMP = "ICMP"
P_ARP = "ARP"
P_DNS = "DNS"
P_HTTP = "HTTP"
P_OTHER = "OTHER"

HTTP_REQUEST_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")


@dataclass
class PacketMeta:
    """Normalized, capture-library-independent view of one packet."""

    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = P_OTHER
    tcp_flags: str = ""            # e.g. "S", "SA", "FA", "PA"
    payload: bytes = b""
    icmp_type: Optional[int] = None
    # ARP fields
    arp_op: Optional[int] = None           # 1 = request, 2 = reply
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None
    # DNS fields
    dns_qname: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_is_response: bool = False
    # Best-effort HTTP parse
    http: Optional[Dict[str, Any]] = None
    raw_len: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    # -- convenience ------------------------------------------------------

    @property
    def payload_text(self) -> str:
        try:
            return self.payload.decode("latin-1", "replace")
        except Exception:  # pragma: no cover - defensive
            return ""

    @property
    def is_tcp_syn(self) -> bool:
        """SYN without ACK - the classic first packet of a connection/probe."""
        return "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def is_tcp_syn_ack(self) -> bool:
        return "S" in self.tcp_flags and "A" in self.tcp_flags

    @property
    def is_tcp_rst(self) -> bool:
        return "R" in self.tcp_flags

    def has_flag(self, letter: str) -> bool:
        return letter in self.tcp_flags

    def http_text(self) -> str:
        """Concatenated request/response text for signature matching."""
        if not self.http:
            return self.payload_text
        parts = [
            str(self.http.get("request_line", "")),
            str(self.http.get("status_line", "")),
            str(self.http.get("path", "")),
            str(self.http.get("body", "")),
            str(self.http.get("user_agent", "")),
            str(self.http.get("host", "")),
        ]
        return "\n".join(p for p in parts if p)

    def tuple_str(self) -> str:
        src = f"{self.src_ip}:{self.src_port}" if self.src_port is not None else str(self.src_ip)
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port is not None else str(self.dst_ip)
        return f"{src} -> {dst}"


def parse_http_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Best-effort HTTP request/response parser for plain-text HTTP/1.x."""
    if not payload:
        return None
    try:
        text = payload.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return None

    head, sep, body = text.partition("\r\n\r\n")
    if not sep:  # tolerate bare LF
        head, sep, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return None

    first = lines[0].strip()
    http: Dict[str, Any] = {"body": body[:4096], "headers": {}, "is_request": False}

    method_path = first.split()
    if len(method_path) >= 2 and method_path[0].upper() in HTTP_REQUEST_METHODS:
        http["is_request"] = True
        http["request_line"] = first
        http["method"] = method_path[0].upper()
        http["path"] = method_path[1]
        http["version"] = method_path[2] if len(method_path) >= 3 else "HTTP/1.0"
    elif first.upper().startswith("HTTP/"):
        http["status_line"] = first
        parts = first.split(None, 2)
        try:
            http["status"] = int(parts[1])
        except (IndexError, ValueError):
            http["status"] = 0
    else:
        return None

    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            http["headers"][key.strip().lower()] = value.strip()
    http["user_agent"] = http["headers"].get("user-agent", "")
    http["host"] = http["headers"].get("host", "")
    http["content_type"] = http["headers"].get("content-type", "")
    return http
