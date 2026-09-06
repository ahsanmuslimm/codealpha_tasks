"""Packet acquisition (scapy): live sniffing, pcap reading, paced replay,
plus normalization of scapy packets into :class:`nids.packets.PacketMeta`.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Iterable, Iterator, Optional

from nids.packets import PacketMeta, parse_http_payload

logger = logging.getLogger("nids.capture")

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, conf, sniff
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - scapy is a hard requirement for capture
    SCAPY_AVAILABLE = False


def require_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for packet capture - install with "
                           "'pip install scapy'")


def list_interfaces() -> list:
    """Return scapy's view of the local interfaces (name + description)."""
    require_scapy()
    result = []
    for name, iface in conf.ifaces.items():
        result.append({
            "name": getattr(iface, "name", name) or name,
            "description": getattr(iface, "description", "") or "",
            "mac": getattr(iface, "mac", "") or "",
            "ip": getattr(iface, "ip", "") or "",
        })
    return result


def normalize(pkt) -> Optional[PacketMeta]:
    """Convert a raw scapy packet to PacketMeta (None for unusable packets)."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        ts = float(getattr(pkt, "time", time.time()))

        if ARP in pkt:
            arp = pkt[ARP]
            return PacketMeta(
                timestamp=ts,
                src_ip=str(arp.psrc),
                dst_ip=str(arp.pdst),
                protocol="ARP",
                arp_op=int(arp.op),
                arp_sender_ip=str(arp.psrc),
                arp_sender_mac=str(arp.hwsrc),
                arp_target_ip=str(arp.pdst),
                arp_target_mac=str(arp.hwdst),
                raw_len=len(pkt),
            )

        if IP in pkt:
            return _normalize_ip(pkt, pkt[IP].src, pkt[IP].dst, ts)
        if IPv6 in pkt:
            return _normalize_ip(pkt, pkt[IPv6].src, pkt[IPv6].dst, ts)
        return None
    except Exception as exc:  # never let one malformed packet kill the engine
        logger.debug("Failed to normalize packet: %s", exc)
        return None


def _normalize_ip(pkt, src: str, dst: str, ts: float) -> Optional[PacketMeta]:
    if TCP in pkt:
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        meta = PacketMeta(
            timestamp=ts, src_ip=src, dst_ip=dst,
            src_port=int(tcp.sport), dst_port=int(tcp.dport),
            protocol="TCP", tcp_flags=str(tcp.flags),
            payload=payload, raw_len=len(pkt),
        )
        http = parse_http_payload(payload)
        if http:
            meta.http = http
        return meta

    if UDP in pkt:
        udp = pkt[UDP]
        meta = PacketMeta(
            timestamp=ts, src_ip=src, dst_ip=dst,
            src_port=int(udp.sport), dst_port=int(udp.dport),
            protocol="UDP", payload=bytes(udp.payload), raw_len=len(pkt),
        )
        if DNS in pkt:
            meta.protocol = "DNS"
            dns = pkt[DNS]
            meta.dns_is_response = bool(dns.qr)
            if DNSQR in pkt:
                try:
                    meta.dns_qname = str(pkt[DNSQR].qname.decode("utf-8", "replace"))
                    meta.dns_qtype = int(pkt[DNSQR].qtype)
                except Exception:
                    pass
        return meta

    if ICMP in pkt:
        icmp = pkt[ICMP]
        return PacketMeta(
            timestamp=ts, src_ip=src, dst_ip=dst, protocol="ICMP",
            icmp_type=int(icmp.type), payload=bytes(icmp.payload), raw_len=len(pkt),
        )
    return PacketMeta(timestamp=ts, src_ip=src, dst_ip=dst, protocol="OTHER",
                      raw_len=len(pkt))


# ---------------------------------------------------------------------------
# Capture sources - every generator yields PacketMeta
# ---------------------------------------------------------------------------


def iter_pcap(path: str) -> Iterator[PacketMeta]:
    """Read a pcap file (works without admin rights)."""
    require_scapy()
    with PcapReader(path) as reader:
        for pkt in reader:
            meta = normalize(pkt)
            if meta is not None:
                yield meta


def iter_live(interface: str, bpf_filter: str = "", promisc: bool = True,
              stop_check: Optional[Callable[[], bool]] = None) -> Iterator[PacketMeta]:
    """Sniff packets from a live interface (requires admin/Npcap on Windows)."""
    require_scapy()
    kwargs = dict(iface=interface or None, filter=bpf_filter or None,
                  store=False, promisc=promisc, timeout=2)
    while True:
        if stop_check is not None and stop_check():
            return
        packets = sniff(**kwargs)
        for pkt in packets:
            meta = normalize(pkt)
            if meta is not None:
                yield meta


def iter_replay(path: str, speed: float = 10.0,
                stop_check: Optional[Callable[[], bool]] = None) -> Iterator[PacketMeta]:
    """Replay a pcap in real time (accelerated by *speed*), preserving gaps."""
    previous_ts: Optional[float] = None
    for meta in iter_pcap(path):
        if stop_check is not None and stop_check():
            return
        if previous_ts is not None and speed > 0:
            delta = (meta.timestamp - previous_ts) / speed
            if 0 < delta <= 30:  # never stall the demo on huge capture gaps
                time.sleep(delta)
        previous_ts = meta.timestamp
        yield meta
