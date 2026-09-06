"""
NetSentry Professional Network Sniffer
========================================

A professional-grade network packet sniffer for cybersecurity analysis.
Built with Python and Scapy for comprehensive packet capture and analysis.

Author: Muhammad Ahsan
Version: 1.0.0
Date: September 6, 2026
License: MIT

Usage:
    python netsentry.py --interface eth0 --count 100 --verbose
    python netsentry.py --file capture.pcap --analyze
    python netsentry.py --interactive
"""

import argparse
import sys
import os
import logging
import datetime
import threading
import queue
import csv
import json
from collections import defaultdict
from typing import Optional, List, Dict, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import socket
import re
import ctypes
import platform

# Check for required dependencies
try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, sendp, Ether, IP, IPv6, TCP, UDP, ICMP, ARP,
        Raw, Padding, NoPayload, conf, get_if_list, get_if_addr
    )
    from scapy.layers.inet import IPError
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(e)

try:
    from colorama import init, Fore, Back, Style
    COLORAMA_AVAILABLE = True
    init()
except ImportError:
    COLORAMA_AVAILABLE = False
    # Define dummy color constants
    class DummyColor:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    Fore = DummyColor()
    Back = DummyColor()
    Style = DummyColor()

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False


# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "1.0.0"
NAME = "NetSentry"
AUTHOR = "Muhammad Ahsan"
DESCRIPTION = "Professional Network Packet Sniffer for Cybersecurity Analysis"

# Protocol colors
PROTOCOL_COLORS = {
    'TCP': Fore.BLUE,
    'UDP': Fore.GREEN,
    'ICMP': Fore.YELLOW,
    'ARP': Fore.MAGENTA,
    'DNS': Fore.CYAN,
    'HTTP': Fore.RED,
    'HTTPS': Fore.RED,
    'FTP': Fore.YELLOW,
    'SSH': Fore.MAGENTA,
    'DHCP': Fore.CYAN,
}

# Default values
DEFAULT_INTERFACE = None  # Auto-detect
DEFAULT_COUNT = 100
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_OUTPUT_FILE = "capture.pcap"
DEFAULT_LOG_FILE = "netsentry.log"

# Well-known ports
WELL_KNOWN_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-SERVER', 68: 'DHCP-CLIENT', 80: 'HTTP',
    110: 'POP3', 123: 'NTP', 137: 'NETBIOS-NS', 138: 'NETBIOS-DGM',
    139: 'NETBIOS-SSN', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-TRAP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'SYSLOG',
    515: 'LPD', 546: 'DHCPv6-CLIENT', 547: 'DHCPv6-SERVER', 587: 'SMTP-SUBMISSION',
    631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MS-SQL',
    1521: 'ORACLE', 1723: 'PPTP', 3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL',
    5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
}


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def setup_logging(log_file: str = DEFAULT_LOG_FILE, level: int = logging.INFO):
    """Configure logging for the application."""
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    return logging.getLogger(NAME)


logger = setup_logging()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_privileges() -> bool:
    """Check if running with administrative privileges."""
    if platform.system() == 'Windows':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def require_privileges():
    """Ensure administrative privileges, exit if not available."""
    if not check_privileges():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {NAME} requires administrative/root privileges.")
        print("Please run with:")
        if platform.system() == 'Windows':
            print("  - Right-click Command Prompt and 'Run as Administrator'")
        else:
            print("  - sudo python netsentry.py")
        sys.exit(1)


def validate_interface(interface: str) -> bool:
    """Validate network interface name."""
    if not interface:
        return True
    return bool(re.match(r'^[a-zA-Z0-9_\-]+$', interface))


def validate_ip(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number."""
    try:
        p = int(port)
        return 0 <= p <= 65535
    except (ValueError, TypeError):
        return False


def sanitize_filter(filter_expr: str) -> str:
    """Sanitize BPF filter expression."""
    if not filter_expr:
        return ""
    # Remove potentially dangerous characters
    return re.sub(r'[;\\"\'\|\&\$\`\<\>\{\}]', '', filter_expr)


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces."""
    try:
        return get_if_list()
    except:
        return []


def get_default_interface() -> Optional[str]:
    """Get the default network interface."""
    try:
        interfaces = get_available_interfaces()
        # Fallback: return first non-loopback interface
        for iface in interfaces:
            if iface != 'lo' and iface != 'lo0':
                return iface
        return interfaces[0] if interfaces else None
    except:
        return None


def format_mac(mac: str) -> str:
    """Format MAC address consistently."""
    if not mac:
        return "N/A"
    # Remove common separators
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
    # Format with colons
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])


def get_protocol_name(proto_num: int) -> str:
    """Get protocol name from number."""
    protocol_map = {
        1: 'ICMP', 2: 'IGMP', 4: 'IPv4', 6: 'TCP', 8: 'EGP',
        12: 'PUP', 17: 'UDP', 20: 'HMP', 22: 'XNS-IDP', 27: 'RDP',
        41: 'IPv6', 43: 'ROUTING', 44: 'FRAGMENT', 46: 'RSVP',
        47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 59: 'NONE',
        103: 'PIM', 112: 'VRRP', 132: 'SCTP',
    }
    return protocol_map.get(proto_num, f"UNKNOWN({proto_num})")


def get_application_protocol(port: int, protocol: str = 'TCP') -> str:
    """Get application protocol from port number."""
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    # Check for common patterns
    if 8000 <= port <= 8999:
        return 'HTTP-ALT'
    if 9000 <= port <= 9999:
        return 'CUSTOM'
    return 'UNKNOWN'


def format_bytes(data: bytes, max_length: int = 100) -> str:
    """Format bytes for display."""
    if not data:
        return ""
    hex_str = data.hex()
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    
    # Truncate if too long
    if len(hex_str) > max_length * 2:
        hex_str = hex_str[:max_length * 2] + "..."
        ascii_str = ascii_str[:max_length] + "..."
    
    # Format in two columns
    lines = []
    for i in range(0, len(hex_str), 32):
        hex_part = hex_str[i:i+32]
        ascii_part = ascii_str[i//2:i//2+16]
        lines.append(f"{hex_part:<32}  {ascii_part}")
    
    return '\n'.join(lines)


def mask_sensitive_data(payload: bytes) -> bytes:
    """Mask sensitive data in payload."""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
    except:
        return payload
    
    # Patterns to mask
    patterns = [
        (r'password\s*[=:]\s*["\']?([^\s"\'&]+)', 'password=*****'),
        (r'passwd\s*[=:]\s*["\']?([^\s"\'&]+)', 'passwd=*****'),
        (r'secret\s*[=:]\s*["\']?([^\s"\'&]+)', 'secret=*****'),
        (r'token\s*[=:]\s*["\']?([^\s"\'&]+)', 'token=*****'),
        (r'api[_-]?key\s*[=:]\s*["\']?([^\s"\'&]+)', 'api_key=*****'),
        (r'authentication\s*[=:]\s*["\']?([^\s"\'&]+)', 'authentication=*****'),
        (r'credential[s]?\s*[=:]\s*["\']?([^\s"\'&]+)', 'credentials=*****'),
    ]
    
    for pattern, replacement in patterns:
        payload_str = re.sub(pattern, replacement, payload_str, flags=re.IGNORECASE)
    
    return payload_str.encode('utf-8')


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class PacketInfo:
    """Comprehensive packet information model."""
    
    # Timestamp
    timestamp: Optional[datetime.datetime] = None
    
    # Link Layer
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ether_type: Optional[str] = None
    
    # Network Layer
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    ip_version: Optional[int] = None
    ttl: Optional[int] = None
    packet_length: Optional[int] = None
    
    # Transport Layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # Application Layer
    app_protocol: Optional[str] = None
    
    # Payload
    payload_hex: Optional[str] = None
    payload_ascii: Optional[str] = None
    payload_raw: Optional[bytes] = None
    
    # Metadata
    interface: Optional[str] = None
    packet_id: Optional[int] = None
    
    # Analysis
    flags: Dict[str, Any] = field(default_factory=dict)
    checksum_valid: Optional[bool] = None
    
    # Security
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now()
    
    def get_protocol_color(self) -> str:
        """Get color for protocol display."""
        if not COLORAMA_AVAILABLE:
            return ""
        return PROTOCOL_COLORS.get(self.protocol or "", Fore.WHITE)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        # Convert datetime to string
        if result.get('timestamp'):
            result['timestamp'] = result['timestamp'].isoformat()
        # Don't include raw bytes in export
        result.pop('payload_raw', None)
        return result
    
    def check_suspicious(self) -> bool:
        """Check if packet is suspicious."""
        reasons = []
        
        # Port scanning detection (destination port < 1024)
        if self.dst_port and self.dst_port < 1024:
            reasons.append(f"Low destination port: {self.dst_port}")
        
        # ICMP flood detection
        if self.protocol == 'ICMP' and (self.packet_length or 0) > 1000:
            reasons.append(f"Large ICMP packet: {self.packet_length} bytes")
        
        # TCP SYN without ACK (potential SYN scan)
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


# =============================================================================
# PACKET CAPTURE ENGINE
# =============================================================================

class PacketCaptureEngine:
    """Engine for capturing network packets."""
    
    def __init__(self):
        self.running = False
        self.packet_queue = queue.Queue()
        self.statistics = Statistics()
        self.captured_packets: List[PacketInfo] = []
    
    def start_capture(
        self,
        interface: Optional[str] = None,
        filter_expr: Optional[str] = None,
        count: Optional[int] = None,
        timeout: Optional[int] = None,
        prn: Optional[Callable] = None,
        store_packets: bool = True,
        output_file: Optional[str] = None,
        verbose: bool = False
    ) -> List[PacketInfo]:
        """
        Start packet capture.
        
        Args:
            interface: Network interface to capture from
            filter_expr: BPF filter expression
            count: Number of packets to capture
            timeout: Capture duration in seconds
            prn: Callback function for each packet
            store_packets: Whether to store packets in memory
            output_file: File to save captured packets
            verbose: Verbose output
        
        Returns:
            List of captured PacketInfo objects
        """
        if not SCAPY_AVAILABLE:
            logger.error(f"Scapy not available: {SCAPY_ERROR}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scapy is required but not installed.")
            print("Install with: pip install scapy")
            return []
        
        require_privileges()
        
        # Validate interface
        if interface and not validate_interface(interface):
            logger.error(f"Invalid interface name: {interface}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid interface name: {interface}")
            return []
        
        # Validate filter
        if filter_expr:
            filter_expr = sanitize_filter(filter_expr)
        
        # Reset statistics
        self.statistics = Statistics()
        self.captured_packets = []
        self.running = True
        
        logger.info(f"Starting capture on interface {interface or 'default'}")
        logger.info(f"Filter: {filter_expr or 'None'}")
        logger.info(f"Count: {count or 'Unlimited'}")
        logger.info(f"Timeout: {timeout or 'Unlimited'} seconds")
        
        if verbose:
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting capture...")
            if interface:
                print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Interface: {interface}")
            if filter_expr:
                print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Filter: {filter_expr}")
        
        packet_count = [0]  # Use list for nonlocal modification
        
        def packet_handler(packet):
            """Handle each captured packet."""
            if not self.running:
                return
            
            try:
                packet_count[0] += 1
                
                # Process packet
                packet_info = self.process_packet(packet, interface)
                packet_info.packet_id = packet_count[0]
                
                # Update statistics
                self.statistics.update(packet_info)
                
                # Store packet
                if store_packets:
                    self.captured_packets.append(packet_info)
                
                # Put in queue for real-time processing
                self.packet_queue.put(packet_info)
                
                # Call custom handler if provided
                if prn:
                    prn(packet_info)
                
                # Save to file
                if output_file and store_packets:
                    # Save raw packet to PCAP
                    wrpcap(output_file, [packet], append=True)
                
                if verbose:
                    self.display_packet_summary(packet_info)
                    
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
        
        try:
            # Start capture
            sniff(
                iface=interface,
                filter=filter_expr,
                count=count,
                timeout=timeout,
                prn=packet_handler,
                store=0  # Don't store in Scapy's memory
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Capture failed: {e}")
            return []
        
        self.running = False
        self.statistics.end_time = datetime.datetime.now()
        
        if verbose:
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Capture complete.")
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Total packets: {len(self.captured_packets)}")
        
        return self.captured_packets
    
    def stop_capture(self):
        """Stop the current capture."""
        self.running = False
    
    def process_packet(self, packet, interface: Optional[str] = None) -> PacketInfo:
        """Process a raw packet into PacketInfo."""
        packet_info = PacketInfo(
            timestamp=datetime.datetime.now(),
            interface=interface or get_default_interface()
        )
        
        # Link Layer (Ethernet)
        if hasattr(packet, 'src') and hasattr(packet, 'dst'):
            packet_info.src_mac = format_mac(packet.src)
            packet_info.dst_mac = format_mac(packet.dst)
            if hasattr(packet, 'type'):
                packet_info.ether_type = packet.type
        
        # Network Layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info.src_ip = ip_layer.src
            packet_info.dst_ip = ip_layer.dst
            packet_info.protocol = get_protocol_name(ip_layer.proto)
            packet_info.ip_version = 4
            packet_info.ttl = ip_layer.ttl
            packet_info.packet_length = ip_layer.len
            
            # Transport Layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.src_port = tcp_layer.sport
                packet_info.dst_port = tcp_layer.dport
                packet_info.protocol = 'TCP'
                packet_info.flags = {
                    'FIN': bool(tcp_layer.flags & 0x01),
                    'SYN': bool(tcp_layer.flags & 0x02),
                    'RST': bool(tcp_layer.flags & 0x04),
                    'PSH': bool(tcp_layer.flags & 0x08),
                    'ACK': bool(tcp_layer.flags & 0x10),
                    'URG': bool(tcp_layer.flags & 0x20),
                }
                
                # Application protocol detection
                if packet_info.dst_port:
                    packet_info.app_protocol = get_application_protocol(packet_info.dst_port, 'TCP')
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info.src_port = udp_layer.sport
                packet_info.dst_port = udp_layer.dport
                packet_info.protocol = 'UDP'
                
                if packet_info.dst_port:
                    packet_info.app_protocol = get_application_protocol(packet_info.dst_port, 'UDP')
                
            elif ICMP in packet:
                packet_info.protocol = 'ICMP'
                
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            packet_info.src_ip = ipv6_layer.src
            packet_info.dst_ip = ipv6_layer.dst
            packet_info.ip_version = 6
            packet_info.protocol = get_protocol_name(ipv6_layer.nh)
            packet_info.packet_length = ipv6_layer.plen
            
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.src_port = tcp_layer.sport
                packet_info.dst_port = tcp_layer.dport
                packet_info.protocol = 'TCP'
                
        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_info.protocol = 'ARP'
            if hasattr(arp_layer, 'psrc'):
                packet_info.src_ip = arp_layer.psrc
            if hasattr(arp_layer, 'pdst'):
                packet_info.dst_ip = arp_layer.pdst
            if hasattr(arp_layer, 'hwsrc'):
                packet_info.src_mac = format_mac(arp_layer.hwsrc)
            if hasattr(arp_layer, 'hwdst'):
                packet_info.dst_mac = format_mac(arp_layer.hwdst)
        
        # Payload extraction
        if hasattr(packet, 'payload') and hasattr(packet.payload, 'load'):
            try:
                payload = bytes(packet.payload.load)
                packet_info.payload_raw = payload
                packet_info.payload_hex = payload.hex()
                try:
                    packet_info.payload_ascii = payload.decode('ascii', errors='replace')
                except:
                    packet_info.payload_ascii = "<non-ascii>"
                
                # Mask sensitive data
                if payload:
                    packet_info.payload_raw = mask_sensitive_data(payload)
                    packet_info.payload_hex = packet_info.payload_raw.hex()
                    try:
                        packet_info.payload_ascii = packet_info.payload_raw.decode('ascii', errors='replace')
                    except:
                        packet_info.payload_ascii = "<non-ascii>"
            except:
                pass
        
        # Check for suspicious activity
        packet_info.check_suspicious()
        
        return packet_info
    
    def display_packet_summary(self, packet_info: PacketInfo):
        """Display a summary of a packet."""
        color = packet_info.get_protocol_color()
        
        # Format the output
        protocol = packet_info.protocol or "UNKNOWN"
        src = packet_info.src_ip or packet_info.src_mac or "N/A"
        dst = packet_info.dst_ip or packet_info.dst_mac or "N/A"
        
        # Port information
        port_info = ""
        if packet_info.src_port and packet_info.dst_port:
            port_info = f":{packet_info.src_port} -> {packet_info.dst_port}"
        
        # Suspicious indicator
        suspicious = ""
        if packet_info.is_suspicious:
            suspicious = f" {Fore.RED}[SUSPICIOUS: {packet_info.suspicious_reason}]{Style.RESET_ALL}"
        
        print(f"{color}[{protocol:6}]{Style.RESET_ALL} {src} -> {dst}{port_info}{suspicious}")
    
    def load_from_pcap(self, filename: str) -> List[PacketInfo]:
        """Load packets from a PCAP file."""
        if not SCAPY_AVAILABLE:
            logger.error(f"Scapy not available: {SCAPY_ERROR}")
            return []
        
        try:
            packets = rdpcap(filename)
            self.captured_packets = []
            self.statistics = Statistics()
            
            for idx, packet in enumerate(packets, 1):
                packet_info = self.process_packet(packet)
                packet_info.packet_id = idx
                self.captured_packets.append(packet_info)
                self.statistics.update(packet_info)
            
            logger.info(f"Loaded {len(self.captured_packets)} packets from {filename}")
            return self.captured_packets
            
        except Exception as e:
            logger.error(f"Error loading PCAP file: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to load {filename}: {e}")
            return []


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

class OutputFormatter:
    """Format packet information for display."""
    
    def __init__(self, use_color: bool = True):
        self.use_color = use_color and COLORAMA_AVAILABLE
    
    def format_packet(self, packet_info: PacketInfo, verbose: bool = False) -> str:
        """Format a single packet for display."""
        lines = []
        
        # Header
        if self.use_color:
            color = packet_info.get_protocol_color()
            lines.append(f"{color}=== Packet #{packet_info.packet_id or 0} ==={Style.RESET_ALL}")
        else:
            lines.append(f"=== Packet #{packet_info.packet_id or 0} ===")
        
        # Timestamp
        if packet_info.timestamp:
            lines.append(f"Timestamp: {packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        
        # Interface
        if packet_info.interface:
            lines.append(f"Interface: {packet_info.interface}")
        
        # Link Layer
        lines.append("")
        lines.append("--- Link Layer (Ethernet) ---")
        lines.append(f"Source MAC: {packet_info.src_mac or 'N/A'}")
        lines.append(f"Dest MAC: {packet_info.dst_mac or 'N/A'}")
        
        # Network Layer
        lines.append("")
        lines.append("--- Network Layer ---")
        lines.append(f"Source IP: {packet_info.src_ip or 'N/A'}")
        lines.append(f"Dest IP: {packet_info.dst_ip or 'N/A'}")
        lines.append(f"Protocol: {packet_info.protocol or 'N/A'}")
        lines.append(f"IP Version: {packet_info.ip_version or 'N/A'}")
        lines.append(f"TTL: {packet_info.ttl or 'N/A'}")
        lines.append(f"Packet Length: {packet_info.packet_length or 'N/A'} bytes")
        
        # Transport Layer
        if packet_info.src_port or packet_info.dst_port:
            lines.append("")
            lines.append("--- Transport Layer ---")
            lines.append(f"Source Port: {packet_info.src_port or 'N/A'}")
            lines.append(f"Dest Port: {packet_info.dst_port or 'N/A'}")
            lines.append(f"App Protocol: {packet_info.app_protocol or 'N/A'}")
            
            if packet_info.flags:
                flags_str = ", ".join([f"{k}={v}" for k, v in packet_info.flags.items()])
                lines.append(f"TCP Flags: {flags_str}")
        
        # Payload
        if verbose and (packet_info.payload_hex or packet_info.payload_ascii):
            lines.append("")
            lines.append("--- Payload ---")
            if packet_info.payload_ascii:
                lines.append(f"ASCII: {packet_info.payload_ascii[:100]}")
            if packet_info.payload_hex:
                lines.append(f"Hex: {packet_info.payload_hex[:100]}")
        
        # Suspicious indicator
        if packet_info.is_suspicious:
            lines.append("")
            if self.use_color:
                lines.append(f"{Fore.RED}[SUSPICIOUS] {packet_info.suspicious_reason}{Style.RESET_ALL}")
            else:
                lines.append(f"[SUSPICIOUS] {packet_info.suspicious_reason}")
        
        return "\n".join(lines)
    
    def format_summary(self, statistics: Statistics) -> str:
        """Format capture statistics summary."""
        lines = []
        summary = statistics.get_summary()
        
        lines.append("")
        lines.append("=" * 60)
        lines.append("CAPTURE STATISTICS SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Total Packets: {summary['total_packets']}")
        lines.append(f"Total Bytes: {summary['total_bytes']}")
        lines.append(f"Suspicious Packets: {summary['suspicious_packets']}")
        lines.append(f"Duration: {summary['duration_seconds']:.2f} seconds")
        lines.append(f"Packets/Second: {summary['packets_per_second']:.2f}")
        lines.append(f"Bytes/Second: {summary['bytes_per_second']:.2f}")
        
        lines.append("")
        lines.append("--- Protocol Distribution ---")
        for proto, count in sorted(summary['packets_by_protocol'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {proto}: {count} packets")
        
        lines.append("")
        lines.append("--- Top Source IPs ---")
        for ip, count in summary['top_source_ips'][:5]:
            lines.append(f"  {ip}: {count} packets")
        
        lines.append("")
        lines.append("--- Top Destination IPs ---")
        for ip, count in summary['top_destination_ips'][:5]:
            lines.append(f"  {ip}: {count} packets")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def format_table(self, packets: List[PacketInfo], max_rows: int = 20) -> str:
        """Format packets as a table."""
        if not TABULATE_AVAILABLE:
            lines = []
            for packet in packets[:max_rows]:
                lines.append(self.format_packet(packet))
            return "\n".join(lines)
        
        headers = ["#", "Time", "Protocol", "Source", "Dest", "Port", "Length", "Status"]
        rows = []
        
        for packet in packets[:max_rows]:
            timestamp = packet.timestamp.strftime('%H:%M:%S.%f')[:-3] if packet.timestamp else "N/A"
            protocol = packet.protocol or "N/A"
            src = packet.src_ip or packet.src_mac or "N/A"
            dst = packet.dst_ip or packet.dst_mac or "N/A"
            port = f"{packet.src_port}→{packet.dst_port}" if packet.src_port and packet.dst_port else "N/A"
            length = f"{packet.packet_length or 0}B"
            status = "SUSPICIOUS" if packet.is_suspicious else "OK"
            
            rows.append([packet.packet_id or 0, timestamp, protocol, src, dst, port, length, status])
        
        return tabulate(rows, headers=headers, tablefmt="grid")


# =============================================================================
# DATA EXPORTERS
# =============================================================================

class DataExporter:
    """Export captured packets to various formats."""
    
    @staticmethod
    def export_to_csv(packets: List[PacketInfo], filename: str) -> bool:
        """Export packets to CSV file."""
        try:
            if not packets:
                logger.warning("No packets to export")
                return False
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'packet_id', 'timestamp', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip',
                    'protocol', 'src_port', 'dst_port', 'app_protocol', 'packet_length',
                    'ttl', 'is_suspicious', 'suspicious_reason'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for packet in packets:
                    row = {
                        'packet_id': packet.packet_id or '',
                        'timestamp': packet.timestamp.isoformat() if packet.timestamp else '',
                        'src_mac': packet.src_mac or '',
                        'dst_mac': packet.dst_mac or '',
                        'src_ip': packet.src_ip or '',
                        'dst_ip': packet.dst_ip or '',
                        'protocol': packet.protocol or '',
                        'src_port': packet.src_port or '',
                        'dst_port': packet.dst_port or '',
                        'app_protocol': packet.app_protocol or '',
                        'packet_length': packet.packet_length or '',
                        'ttl': packet.ttl or '',
                        'is_suspicious': packet.is_suspicious,
                        'suspicious_reason': packet.suspicious_reason or ''
                    }
                    writer.writerow(row)
            
            logger.info(f"Exported {len(packets)} packets to {filename}")
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export: {e}")
            return False
    
    @staticmethod
    def export_to_json(packets: List[PacketInfo], filename: str) -> bool:
        """Export packets to JSON file."""
        try:
            if not packets:
                logger.warning("No packets to export")
                return False
            
            data = {
                'export_date': datetime.datetime.now().isoformat(),
                'total_packets': len(packets),
                'packets': [packet.to_dict() for packet in packets]
            }
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, default=str)
            
            logger.info(f"Exported {len(packets)} packets to {filename}")
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export: {e}")
            return False
    
    @staticmethod
    def export_to_html(packets: List[PacketInfo], statistics: Statistics, filename: str) -> bool:
        """Export packets and statistics to HTML report."""
        try:
            if not packets:
                logger.warning("No packets to export")
                return False
            
            html = []
            html.append("<!DOCTYPE html>")
            html.append("<html>")
            html.append("<head>")
            html.append(f"<title>{NAME} - Packet Capture Report</title>")
            html.append("<style>")
            html.append("body { font-family: Arial, sans-serif; margin: 20px; }")
            html.append("h1, h2 { color: #333; }")
            html.append("table { border-collapse: collapse; width: 100%; margin: 20px 0; }")
            html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
            html.append("th { background-color: #4CAF50; color: white; }")
            html.append("tr:nth-child(even) { background-color: #f2f2f2; }")
            html.append(".suspicious { background-color: #ffcccc; }")
            html.append("</style>")
            html.append("</head>")
            html.append("<body>")
            
            html.append(f"<h1>{NAME} - Packet Capture Report</h1>")
            html.append(f"<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
            
            # Summary
            summary = statistics.get_summary()
            html.append("<h2>Summary Statistics</h2>")
            html.append("<table>")
            html.append("<tr><th>Metric</th><th>Value</th></tr>")
            html.append(f"<tr><td>Total Packets</td><td>{summary['total_packets']}</td></tr>")
            html.append(f"<tr><td>Total Bytes</td><td>{summary['total_bytes']}</td></tr>")
            html.append(f"<tr><td>Suspicious Packets</td><td>{summary['suspicious_packets']}</td></tr>")
            html.append(f"<tr><td>Duration (s)</td><td>{summary['duration_seconds']:.2f}</td></tr>")
            html.append(f"<tr><td>Packets/Second</td><td>{summary['packets_per_second']:.2f}</td></tr>")
            html.append("</table>")
            
            # Protocol Distribution
            html.append("<h2>Protocol Distribution</h2>")
            html.append("<table>")
            html.append("<tr><th>Protocol</th><th>Count</th><th>Bytes</th></tr>")
            for proto in sorted(summary['packets_by_protocol'].keys()):
                count = summary['packets_by_protocol'][proto]
                bytes_count = summary['bytes_by_protocol'].get(proto, 0)
                html.append(f"<tr><td>{proto}</td><td>{count}</td><td>{bytes_count}</td></tr>")
            html.append("</table>")
            
            # Packets
            html.append("<h2>Captured Packets</h2>")
            html.append("<table>")
            html.append("<tr><th>#</th><th>Time</th><th>Protocol</th><th>Source</th><th>Dest</th><th>Port</th><th>Length</th><th>Status</th></tr>")
            
            for packet in packets:
                timestamp = packet.timestamp.strftime('%H:%M:%S.%f')[:-3] if packet.timestamp else "N/A"
                src = packet.src_ip or packet.src_mac or "N/A"
                dst = packet.dst_ip or packet.dst_mac or "N/A"
                port = f"{packet.src_port}→{packet.dst_port}" if packet.src_port and packet.dst_port else "N/A"
                status = "SUSPICIOUS" if packet.is_suspicious else "OK"
                row_class = 'class="suspicious"' if packet.is_suspicious else ""
                
                html.append(f"<tr {row_class}>")
                html.append(f"<td>{packet.packet_id or 0}</td>")
                html.append(f"<td>{timestamp}</td>")
                html.append(f"<td>{packet.protocol or 'N/A'}</td>")
                html.append(f"<td>{src}</td>")
                html.append(f"<td>{dst}</td>")
                html.append(f"<td>{port}</td>")
                html.append(f"<td>{packet.packet_length or 0}</td>")
                html.append(f"<td>{status}</td>")
                html.append("</tr>")
            
            html.append("</table>")
            html.append("</body>")
            html.append("</html>")
            
            with open(filename, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write("\n".join(html))
            
            logger.info(f"Exported {len(packets)} packets to HTML report: {filename}")
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Report exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to HTML: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export: {e}")
            return False


# =============================================================================
# INTERACTIVE MODE
# =============================================================================

class InteractiveMode:
    """Interactive CLI interface for NetSentry."""
    
    def __init__(self):
        self.engine = PacketCaptureEngine()
        self.formatter = OutputFormatter()
        self.running = True
    
    def run(self):
        """Run the interactive mode."""
        print(f"\n{Fore.CYAN}Welcome to {NAME} v{VERSION}{Style.RESET_ALL}")
        print(f"Professional Network Packet Sniffer")
        print(f"Type 'help' for available commands\n")
        
        while self.running:
            try:
                command = input(f"{Fore.GREEN}netsentry>{Style.RESET_ALL} ").strip().lower()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd == 'start':
                    self.interactive_capture()
                elif cmd == 'load':
                    self.interactive_load()
                elif cmd == 'analyze':
                    self.interactive_analyze()
                elif cmd == 'export':
                    self.interactive_export()
                elif cmd == 'stats':
                    self.display_statistics()
                elif cmd == 'interfaces':
                    self.list_interfaces()
                elif cmd == 'help':
                    self.display_help()
                elif cmd == 'quit' or cmd == 'exit':
                    print("Goodbye!")
                    self.running = False
                else:
                    print(f"{Fore.YELLOW}Unknown command: {cmd}{Style.RESET_ALL}")
                    print("Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n" + f"{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    
    def display_help(self):
        """Display help information."""
        print("\n" + "=" * 60)
        print("AVAILABLE COMMANDS")
        print("=" * 60)
        print("  start       - Start packet capture")
        print("  load        - Load packets from PCAP file")
        print("  analyze     - Analyze captured packets")
        print("  export      - Export packets to file")
        print("  stats       - Display capture statistics")
        print("  interfaces  - List available network interfaces")
        print("  help        - Show this help message")
        print("  quit/exit   - Exit the program")
        print("=" * 60 + "\n")
    
    def list_interfaces(self):
        """List available network interfaces."""
        interfaces = get_available_interfaces()
        if interfaces:
            print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
            for iface in interfaces:
                print(f"  - {iface}")
            print()
        else:
            print(f"{Fore.YELLOW}No network interfaces found{Style.RESET_ALL}")
    
    def interactive_capture(self):
        """Interactive packet capture."""
        print(f"\n{Fore.CYAN}=== Packet Capture ==={Style.RESET_ALL}")
        
        # Get interface
        interfaces = get_available_interfaces()
        if not interfaces:
            print(f"{Fore.RED}No network interfaces available{Style.RESET_ALL}")
            return
        
        print("Available interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface}")
        
        try:
            choice = int(input("Select interface (number or Enter for default): ") or "-1")
            interface = interfaces[choice] if 0 <= choice < len(interfaces) else None
        except ValueError:
            interface = None
        
        # Get count
        try:
            count = int(input("Number of packets to capture (or Enter for 100): ") or "100")
        except ValueError:
            count = 100
        
        # Get timeout
        try:
            timeout = int(input("Timeout in seconds (or Enter for 30): ") or "30")
        except ValueError:
            timeout = 30
        
        # Get filter
        filter_expr = input("BPF filter (optional, press Enter to skip): ").strip()
        
        # Get output file
        output_file = input("Save to PCAP file (optional, press Enter to skip): ").strip() or None
        
        # Start capture
        verbose = input("Verbose output? (y/n, default=n): ").lower() == 'y'
        
        print(f"\n{Fore.CYAN}Starting capture...{Style.RESET_ALL}")
        self.engine.start_capture(
            interface=interface,
            filter_expr=filter_expr or None,
            count=count,
            timeout=timeout,
            output_file=output_file,
            verbose=verbose
        )
        
        print(self.formatter.format_summary(self.engine.statistics))
    
    def interactive_load(self):
        """Load packets from PCAP file."""
        print(f"\n{Fore.CYAN}=== Load PCAP File ==={Style.RESET_ALL}")
        
        filename = input("Enter PCAP file path: ").strip()
        if not filename:
            print("Cancelled")
            return
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}File not found: {filename}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Loading packets...{Style.RESET_ALL}")
        packets = self.engine.load_from_pcap(filename)
        
        if packets:
            print(f"{Fore.GREEN}Loaded {len(packets)} packets{Style.RESET_ALL}")
            print(self.formatter.format_summary(self.engine.statistics))
        else:
            print(f"{Fore.RED}Failed to load packets{Style.RESET_ALL}")
    
    def interactive_analyze(self):
        """Analyze captured packets."""
        packets = self.engine.captured_packets
        if not packets:
            print(f"{Fore.YELLOW}No packets captured or loaded{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== Packet Analysis ==={Style.RESET_ALL}")
        
        # Show table
        print("\n" + self.formatter.format_table(packets))
        
        # Detailed view
        try:
            packet_num = int(input("\nEnter packet number for detailed view (or 0 to skip): ") or "0")
            if packet_num > 0 and packet_num <= len(packets):
                packet = packets[packet_num - 1]
                print("\n" + self.formatter.format_packet(packet, verbose=True))
        except ValueError:
            pass
    
    def interactive_export(self):
        """Export packets to file."""
        packets = self.engine.captured_packets
        if not packets:
            print(f"{Fore.YELLOW}No packets to export{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== Export Packets ==={Style.RESET_ALL}")
        print("Export formats:")
        print("  1. CSV")
        print("  2. JSON")
        print("  3. HTML Report")
        
        try:
            choice = int(input("Select format (1-3): ") or "0")
        except ValueError:
            choice = 0
        
        if choice not in [1, 2, 3]:
            print("Invalid choice")
            return
        
        filename = input("Enter output filename: ").strip()
        if not filename:
            print("Cancelled")
            return
        
        if choice == 1:
            DataExporter.export_to_csv(packets, filename)
        elif choice == 2:
            DataExporter.export_to_json(packets, filename)
        elif choice == 3:
            DataExporter.export_to_html(packets, self.engine.statistics, filename)
    
    def display_statistics(self):
        """Display capture statistics."""
        if not self.engine.captured_packets:
            print(f"{Fore.YELLOW}No packets captured or loaded{Style.RESET_ALL}")
            return
        
        print(self.formatter.format_summary(self.engine.statistics))


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{NAME} - {DESCRIPTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netsentry.py --interface eth0 --count 100
  python netsentry.py --interface eth0 --filter "tcp port 80" --verbose
  python netsentry.py --file capture.pcap --analyze
  python netsentry.py --file capture.pcap --export csv --output-file results.csv
  python netsentry.py --interactive
        """
    )
    
    # Capture options
    capture_group = parser.add_argument_group('Capture Options')
    capture_group.add_argument('--interface', '-i', help='Network interface to capture from')
    capture_group.add_argument('--count', '-c', type=int, default=100, help='Number of packets to capture (default: 100)')
    capture_group.add_argument('--timeout', '-t', type=int, default=30, help='Capture timeout in seconds (default: 30)')
    capture_group.add_argument('--filter', '-f', help='BPF filter expression')
    capture_group.add_argument('--output', '-o', help='Output PCAP file')
    
    # File options
    file_group = parser.add_argument_group('File Options')
    file_group.add_argument('--file', help='Load packets from PCAP file')
    file_group.add_argument('--analyze', action='store_true', help='Analyze loaded packets')
    
    # Export options
    export_group = parser.add_argument_group('Export Options')
    export_group.add_argument('--export', choices=['csv', 'json', 'report'], help='Export format')
    export_group.add_argument('--output-file', help='Export output filename')
    
    # Display options
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    display_group.add_argument('--interactive', action='store_true', help='Interactive mode')
    display_group.add_argument('--list-interfaces', action='store_true', help='List network interfaces')
    
    # Info options
    info_group = parser.add_argument_group('Information')
    info_group.add_argument('--version', action='version', version=f'{NAME} {VERSION}')
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Interactive mode
    if args.interactive:
        mode = InteractiveMode()
        mode.run()
        return
    
    # List interfaces
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        if interfaces:
            print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
            for iface in interfaces:
                print(f"  - {iface}")
            print()
        else:
            print(f"{Fore.RED}No network interfaces found{Style.RESET_ALL}")
        return
    
    # Load and analyze PCAP file
    if args.file:
        engine = PacketCaptureEngine()
        packets = engine.load_from_pcap(args.file)
        
        if not packets:
            print(f"{Fore.RED}Failed to load packets{Style.RESET_ALL}")
            return
        
        formatter = OutputFormatter()
        
        # Display analysis
        if args.analyze:
            print(formatter.format_table(packets))
            print(formatter.format_summary(engine.statistics))
        
        # Export packets
        if args.export and args.output_file:
            if args.export == 'csv':
                DataExporter.export_to_csv(packets, args.output_file)
            elif args.export == 'json':
                DataExporter.export_to_json(packets, args.output_file)
            elif args.export == 'report':
                DataExporter.export_to_html(packets, engine.statistics, args.output_file)
        
        return
    
    # Start capture
    engine = PacketCaptureEngine()
    packets = engine.start_capture(
        interface=args.interface,
        filter_expr=args.filter,
        count=args.count,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose
    )
    
    if packets:
        formatter = OutputFormatter()
        print(formatter.format_summary(engine.statistics))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Capture stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"{Fore.RED}[FATAL ERROR]{Style.RESET_ALL} {e}")
        sys.exit(1)
