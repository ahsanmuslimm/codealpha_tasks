"""Data models for NetSentry."""

import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Union
from collections import defaultdict


@dataclass
class PacketInfo:
    """Comprehensive packet information model."""
    
    timestamp: Optional[datetime.datetime] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ether_type: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    ip_version: Optional[int] = None
    ttl: Optional[int] = None
    packet_length: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    app_protocol: Optional[str] = None
    payload_hex: Optional[str] = None
    payload_ascii: Optional[str] = None
    payload_raw: Optional[bytes] = None
    interface: Optional[str] = None
    packet_id: Optional[int] = None
    flags: Dict[str, Any] = field(default_factory=dict)
    checksum_valid: Optional[bool] = None
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now()
    
    def get_protocol_color(self) -> str:
        """Get color for protocol display."""
        try:
            from colorama import Fore
            PROTOCOL_COLORS = {
                'TCP': Fore.BLUE,
                'UDP': Fore.GREEN,
                'ICMP': Fore.YELLOW,
                'ARP': Fore.MAGENTA,
                'DNS': Fore.CYAN,
                'HTTP': Fore.RED,
                'HTTPS': Fore.RED,
            }
            return PROTOCOL_COLORS.get(self.protocol or "", "")
        except:
            return ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if result.get('timestamp'):
            result['timestamp'] = result['timestamp'].isoformat()
        result.pop('payload_raw', None)
        return result
    
    def check_suspicious(self) -> bool:
        """Check if packet is suspicious."""
        reasons = []
        if self.dst_port and self.dst_port < 1024:
            reasons.append(f"Low destination port: {self.dst_port}")
        if self.protocol == 'ICMP' and (self.packet_length or 0) > 1000:
            reasons.append(f"Large ICMP packet: {self.packet_length} bytes")
        if self.protocol == 'TCP' and self.flags.get('SYN') and not self.flags.get('ACK'):
            reasons.append("TCP SYN without ACK")
        self.is_suspicious = len(reasons) > 0
        self.suspicious_reason = "; ".join(reasons) if reasons else None
        return self.is_suspicious


@dataclass
class Filter:
    """Network traffic filter."""
    filter_type: str
    value: Union[str, int]
    operator: str = "=="
    
    def to_bpf(self) -> str:
        """Convert to BPF filter string."""
        type_map = {
            'src_ip': 'src host',
            'dst_ip': 'dst host',
            'ip': 'host',
            'src_port': 'src port',
            'dst_port': 'dst port',
            'port': 'port',
            'protocol': '',
            'src_mac': 'src ether',
            'dst_mac': 'dst ether',
            'size': 'len',
        }
        bpf_type = type_map.get(self.filter_type, "")
        if self.filter_type == 'protocol':
            return f"{self.value}"
        return f"{bpf_type} {self.operator} {self.value}".strip()


class FilterManager:
    """Manage multiple filters with AND/OR logic."""
    
    def __init__(self):
        self.filters: List[Filter] = []
        self.logic: str = "AND"
    
    def add_filter(self, filter_type: str, value: Union[str, int], operator: str = "=="):
        """Add a filter."""
        self.filters.append(Filter(filter_type, value, operator))
    
    def to_bpf(self) -> str:
        """Generate BPF filter string."""
        if not self.filters:
            return ""
        bpf_filters = [f.to_bpf() for f in self.filters if f.to_bpf()]
        return f"({f' {self.logic} '.join(bpf_filters)})" if bpf_filters else ""


@dataclass
class Statistics:
    """Capture statistics."""
    total_packets: int = 0
    total_bytes: int = 0
    packets_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    bytes_by_protocol: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    source_ips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    destination_ips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    suspicious_count: int = 0
    
    def update(self, packet: PacketInfo):
        """Update statistics with a new packet."""
        if self.start_time is None:
            self.start_time = packet.timestamp or datetime.datetime.now()
        self.end_time = packet.timestamp or datetime.datetime.now()
        
        self.total_packets += 1
        self.total_bytes += packet.packet_length or 0
        
        if packet.protocol:
            self.packets_by_protocol[packet.protocol] += 1
            self.bytes_by_protocol[packet.protocol] += packet.packet_length or 0
        
        if packet.src_ip:
            self.source_ips[packet.src_ip] += 1
        
        if packet.dst_ip:
            self.destination_ips[packet.dst_ip] += 1
        
        if packet.is_suspicious:
            self.suspicious_count += 1
    
    def get_duration(self) -> float:
        """Get capture duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        duration = self.get_duration()
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'suspicious_packets': self.suspicious_count,
            'duration_seconds': duration,
            'packets_per_second': self.total_packets / duration if duration > 0 else 0,
            'bytes_per_second': self.total_bytes / duration if duration > 0 else 0,
            'packets_by_protocol': dict(self.packets_by_protocol),
            'bytes_by_protocol': dict(self.bytes_by_protocol),
            'top_source_ips': sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_destination_ips': sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:10],
        }
