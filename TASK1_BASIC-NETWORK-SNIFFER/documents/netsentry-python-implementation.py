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
            print("  - Right-click and 'Run as Administrator'")
        else:
            print("  - sudo netsentry")
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
        # Try to get the interface with a default route
        if platform.system() == 'Windows':
            # Windows specific
            import subprocess
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line or 'default' in line.lower():
                    parts = line.split()
                    for part in parts:
                        if part in get_available_interfaces():
                            return part
        else:
            # Linux/macOS
            import subprocess
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    for part in parts:
                        if part in get_available_interfaces():
                            return part
    except:
        pass
    
    # Fallback: return first non-loopback interface
    interfaces = get_available_interfaces()
    for iface in interfaces:
        if iface != 'lo' and iface != 'lo0':
            return iface
    
    return interfaces[0] if interfaces else None


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
        
        # Multiple destination ports in single packet (impossible, but check)
        # This would be caught at the packet level
        
        self.is_suspicious = len(reasons) > 0
        self.suspicious_reason = "; ".join(reasons)
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
        return f"{bpf_type} {self.operator} {self.value}"


class FilterManager:
    """Manage multiple filters with AND/OR logic."""
    
    def __init__(self):
        self.filters: List[Filter] = []
        self.logic: str = "AND"
    
    def add_filter(self, filter_type: str, value: Union[str, int], operator: str = "=="):
        self.filters.append(Filter(filter_type, value, operator))
    
    def to_bpf(self) -> str:
        """Generate BPF filter string."""
        if not self.filters:
            return ""
        
        bpf_filters = [f.to_bpf() for f in self.filters]
        return f"({' ' + self.logic + ' '.join(bpf_filters)})"


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
            try:
                # Test if filter is valid
                from scapy.all import compile_filter
                compile_filter(filter_expr)
            except Exception as e:
                logger.error(f"Invalid filter expression: {filter_expr}, error: {e}")
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid filter: {e}")
                return []
        
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
        
        def packet_handler(packet):
            """Handle each captured packet."""
            if not self.running:
                return
            
            try:
                # Process packet
                packet_info = self.process_packet(packet, interface)
                
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
            packet_info.checksum_valid = ip_layer.chksum == 0  # 0 means valid in Scapy
            
            # Transport Layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.src_port = tcp_layer.sport
                packet_info.dst_port = tcp_layer.dport
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
            
            for packet in packets:
                packet_info = self.process_packet(packet)
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
            lines.append(f"{color}=== Packet #{packet_info.packet_id or len(lines) + 1} ==={Style.RESET_ALL}")
        else:
            lines.append(f"=== Packet #{packet_info.packet_id or len(lines) + 1} ===")
        
        # Timestamp
        if packet_info.timestamp:
            lines.append(f"Timestamp: {packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}")
        
        # Interface
        if packet_info.interface:
            lines.append(f"Interface: {packet_info.interface}")
        
        # Link Layer
        lines.append("")
        lines.append("--- Link Layer (Ethernet) ---")
        lines.append(f"Source MAC: {packet_info.src_mac or 'N/A'}")
        lines.append(f"Dest MAC: {packet_info.dst_mac or 'N/A'}")
        lines.append(f"Ether Type: {packet_info.ether_type or 'N/A'}")
        
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
            if packet_info.app_protocol:
                lines.append(f"Application Protocol: {packet_info.app_protocol}")
            
            # TCP Flags
            if packet_info.flags:
                flags_str = ", ".join([f"{k}={v}" for k, v in packet_info.flags.items()])
                lines.append(f"Flags: {flags_str}")
        
        # Payload
        if packet_info.payload_raw and (verbose or not packet_info.is_suspicious):
            lines.append("")
            lines.append("--- Payload ---")
            lines.append(f"Size: {len(packet_info.payload_raw)} bytes")
            lines.append("")
            lines.append("Hex:")
            lines.append(format_bytes(packet_info.payload_raw, max_length=50))
            lines.append("")
            lines.append("ASCII:")
            lines.append(packet_info.payload_ascii or "")
        elif packet_info.is_suspicious:
            lines.append("")
            lines.append(f"--- Payload ---")
            lines.append(f"{Fore.RED}[MASKED - Suspicious Packet]{Style.RESET_ALL}")
        
        # Security
        if packet_info.is_suspicious:
            lines.append("")
            lines.append(f"{Fore.RED}--- SECURITY ALERT ---{Style.RESET_ALL}")
            lines.append(f"Reason: {packet_info.suspicious_reason}")
        
        return "\n".join(lines)
    
    def format_summary(self, statistics: Statistics) -> str:
        """Format capture summary."""
        summary = statistics.get_summary()
        lines = []
        
        lines.append("")
        lines.append("=" * 60)
        lines.append("CAPTURE SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Total Packets: {summary['total_packets']}")
        lines.append(f"Total Bytes: {summary['total_bytes']}")
        lines.append(f"Duration: {summary['duration_seconds']:.2f} seconds")
        lines.append(f"Packets/sec: {summary['packets_per_second']:.2f}")
        lines.append(f"Bytes/sec: {summary['bytes_per_second']:.2f}")
        
        lines.append("")
        lines.append("--- Protocol Distribution ---")
        if TABULATE_AVAILABLE:
            protocol_table = []
            for proto, count in sorted(summary['packets_by_protocol'].items(), key=lambda x: x[1], reverse=True):
                bytes_count = summary['bytes_by_protocol'].get(proto, 0)
                protocol_table.append([proto, count, bytes_count])
            lines.append(tabulate(protocol_table, headers=['Protocol', 'Packets', 'Bytes'], tablefmt='grid'))
        else:
            for proto, count in sorted(summary['packets_by_protocol'].items(), key=lambda x: x[1], reverse=True):
                bytes_count = summary['bytes_by_protocol'].get(proto, 0)
                lines.append(f"  {proto}: {count} packets, {bytes_count} bytes")
        
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
        if not packets:
            return "No packets captured."
        
        # Limit rows
        display_packets = packets[:max_rows]
        
        if TABULATE_AVAILABLE:
            table_data = []
            for i, packet in enumerate(display_packets, 1):
                color = packet.get_protocol_color() if self.use_color else ""
                protocol = f"{color}{packet.protocol or '?'}{Style.RESET_ALL}" if self.use_color else (packet.protocol or '?')
                src = packet.src_ip or packet.src_mac or 'N/A'
                dst = packet.dst_ip or packet.dst_mac or 'N/A'
                port = f"{packet.src_port}:{packet.dst_port}" if packet.src_port and packet.dst_port else ""
                length = packet.packet_length or 0
                suspicious = "YES" if packet.is_suspicious else ""
                
                table_data.append([i, protocol, src, dst, port, length, suspicious])
            
            headers = ['#', 'Protocol', 'Source', 'Destination', 'Ports', 'Length', 'Suspicious']
            return tabulate(table_data, headers=headers, tablefmt='grid')
        else:
            lines = []
            lines.append(f"{'#':<4} {'Protocol':<10} {'Source':<20} {'Destination':<20} {'Ports':<10} {'Length':<8} {'Suspicious':<10}")
            lines.append("-" * 82)
            for i, packet in enumerate(display_packets, 1):
                protocol = packet.protocol or '?'
                src = (packet.src_ip or packet.src_mac or 'N/A')[:20]
                dst = (packet.dst_ip or packet.dst_mac or 'N/A')[:20]
                port = f"{packet.src_port}:{packet.dst_port}" if packet.src_port and packet.dst_port else ""
                length = packet.packet_length or 0
                suspicious = "YES" if packet.is_suspicious else ""
                lines.append(f"{i:<4} {protocol:<10} {src:<20} {dst:<20} {port:<10} {length:<8} {suspicious:<10}")
            return "\n".join(lines)


# =============================================================================
# EXPORTERS
# =============================================================================

class DataExporter:
    """Export captured data to various formats."""
    
    @staticmethod
    def export_to_csv(packets: List[PacketInfo], filename: str) -> bool:
        """Export packets to CSV file."""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                header = [
                    'packet_id', 'timestamp', 'interface', 'src_mac', 'dst_mac',
                    'src_ip', 'dst_ip', 'protocol', 'ip_version', 'ttl',
                    'packet_length', 'src_port', 'dst_port', 'app_protocol',
                    'is_suspicious', 'suspicious_reason'
                ]
                writer.writerow(header)
                
                # Write data
                for i, packet in enumerate(packets, 1):
                    row = [
                        i,
                        packet.timestamp.isoformat() if packet.timestamp else '',
                        packet.interface or '',
                        packet.src_mac or '',
                        packet.dst_mac or '',
                        packet.src_ip or '',
                        packet.dst_ip or '',
                        packet.protocol or '',
                        packet.ip_version or '',
                        packet.ttl or '',
                        packet.packet_length or '',
                        packet.src_port or '',
                        packet.dst_port or '',
                        packet.app_protocol or '',
                        'YES' if packet.is_suspicious else 'NO',
                        packet.suspicious_reason or ''
                    ]
                    writer.writerow(row)
            
            logger.info(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"CSV export error: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export to CSV: {e}")
            return False
    
    @staticmethod
    def export_to_json(packets: List[PacketInfo], filename: str) -> bool:
        """Export packets to JSON file."""
        try:
            data = {
                'version': VERSION,
                'timestamp': datetime.datetime.now().isoformat(),
                'total_packets': len(packets),
                'packets': [packet.to_dict() for packet in packets]
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"JSON export error: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export to JSON: {e}")
            return False
    
    @staticmethod
    def export_report(packets: List[PacketInfo], statistics: Statistics, filename: str) -> bool:
        """Export a text report."""
        try:
            formatter = OutputFormatter(use_color=False)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"{NAME} - Capture Report\n")
                f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Version: {VERSION}\n\n")
                
                f.write(formatter.format_summary(statistics))
                f.write("\n\n")
                
                f.write("DETAILED PACKETS\n")
                f.write("=" * 60 + "\n\n")
                
                for i, packet in enumerate(packets, 1):
                    f.write(f"\n{Packet Separator}\n")
                    f.write(f"Packet #{i}\n")
                    f.write(f"{Packet Separator}\n")
                    f.write(formatter.format_packet(packet, verbose=True))
                    f.write("\n")
            
            logger.info(f"Exported report to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Report export error: {e}")
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to export report: {e}")
            return False


# =============================================================================
# INTERACTIVE MODE
# =============================================================================

class InteractiveMode:
    """Interactive command-line interface."""
    
    def __init__(self):
        self.engine = PacketCaptureEngine()
        self.formatter = OutputFormatter()
        self.exporter = DataExporter()
    
    def run(self):
        """Run interactive mode."""
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{NAME} v{VERSION} - Interactive Mode{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print()
        
        while True:
            try:
                self.display_menu()
                choice = input(f"{Fore.GREEN}netsentry> {Style.RESET_ALL}").strip()
                
                if not choice:
                    continue
                
                if choice.lower() in ['exit', 'quit', 'q']:
                    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Exiting...")
                    break
                
                elif choice.lower() in ['help', 'h', '?']:
                    self.display_help()
                
                elif choice.lower() in ['interfaces', 'ifaces', 'i']:
                    self.list_interfaces()
                
                elif choice.lower() in ['capture', 'c']:
                    self.interactive_capture()
                
                elif choice.lower() in ['load', 'l']:
                    self.interactive_load()
                
                elif choice.lower() in ['analyze', 'a']:
                    self.interactive_analyze()
                
                elif choice.lower() in ['export', 'e']:
                    self.interactive_export()
                
                elif choice.lower() in ['stats', 's']:
                    self.display_statistics()
                
                elif choice.lower() in ['clear', 'clr']:
                    os.system('cls' if platform.system() == 'Windows' else 'clear')
                
                else:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unknown command: {choice}")
                    print("Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Use 'exit' or 'quit' to exit.")
            except Exception as e:
                logger.error(f"Interactive mode error: {e}")
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")
    
    def display_menu(self):
        """Display the main menu."""
        menu = f"""
{Fore.CYAN}Main Menu:{Style.RESET_ALL}
  {Fore.GREEN}capture, c{Style.RESET_ALL}    - Start packet capture
  {Fore.GREEN}load, l{Style.RESET_ALL}      - Load packets from PCAP file
  {Fore.GREEN}analyze, a{Style.RESET_ALL}   - Analyze loaded packets
  {Fore.GREEN}export, e{Style.RESET_ALL}    - Export captured data
  {Fore.GREEN}stats, s{Style.RESET_ALL}     - Show capture statistics
  {Fore.GREEN}interfaces, i{Style.RESET_ALL} - List available interfaces
  {Fore.GREEN}help, h, ?{Style.RESET_ALL}   - Show this help
  {Fore.GREEN}clear, clr{Style.RESET_ALL}    - Clear screen
  {Fore.GREEN}exit, quit, q{Style.RESET_ALL} - Exit
"""
        print(menu)
    
    def display_help(self):
        """Display detailed help."""
        help_text = f"""
{Fore.CYAN}{NAME} v{VERSION} - Help{Style.RESET_ALL}

{Fore.YELLOW}Commands:{Style.RESET_ALL}

  {Fore.GREEN}capture [options]{Style.RESET_ALL}
    Start packet capture with optional parameters:
    --interface, -i <iface>   : Network interface
    --filter, -f <expr>      : BPF filter expression
    --count, -c <n>          : Number of packets to capture
    --timeout, -t <sec>      : Capture duration in seconds
    --output, -o <file>      : Save to PCAP file
    --verbose, -v            : Verbose output
    
    Example: capture -i eth0 -f "tcp port 80" -c 100 -o web.pcap

  {Fore.GREEN}load <file>{Style.RESET_ALL}
    Load packets from a PCAP file.
    Example: load capture.pcap

  {Fore.GREEN}analyze [options]{Style.RESET_ALL}
    Analyze loaded packets:
    --packet, -p <n>         : Show specific packet
    --all, -a               : Show all packets
    --table, -t             : Show as table
    --verbose, -v           : Verbose output
    
    Example: analyze -p 1 -v

  {Fore.GREEN}export [format] <file>{Style.RESET_ALL}
    Export captured data:
    csv <file>              : Export to CSV
    json <file>            : Export to JSON
    report <file>          : Export text report
    
    Example: export csv output.csv

  {Fore.GREEN}stats{Style.RESET_ALL}
    Show capture statistics summary.

  {Fore.GREEN}interfaces{Style.RESET_ALL}
    List available network interfaces.

  {Fore.GREEN}help, ?, h{Style.RESET_ALL}
    Show this help message.

  {Fore.GREEN}clear, clr{Style.RESET_ALL}
    Clear the screen.

  {Fore.GREEN}exit, quit, q{Style.RESET_ALL}
    Exit the application.

{Fore.YELLOW}Notes:{Style.RESET_ALL}
- Commands can be abbreviated (e.g., 'c' for 'capture')
- Use Tab for auto-completion (if supported)
- Use Ctrl+C to cancel current operation
"""
        print(help_text)
    
    def list_interfaces(self):
        """List available network interfaces."""
        interfaces = get_available_interfaces()
        if not interfaces:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No network interfaces found.")
            return
        
        print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
        print("-" * 40)
        
        default = get_default_interface()
        for iface in interfaces:
            marker = " *" if iface == default else ""
            try:
                addr = get_if_addr(iface)
                print(f"  {iface}{marker}: {addr}")
            except:
                print(f"  {iface}{marker}: <no address>")
        
        print()
    
    def interactive_capture(self):
        """Interactive packet capture."""
        print(f"\n{Fore.CYAN}Capture Configuration{Style.RESET_ALL}")
        print("-" * 40)
        
        # Get interface
        interfaces = get_available_interfaces()
        if not interfaces:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No network interfaces available.")
            return
        
        default_iface = get_default_interface()
        interface = input(f"Interface [{default_iface}]: ").strip()
        if not interface:
            interface = default_iface
        
        if interface not in interfaces and interface != '':
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid interface: {interface}")
            return
        
        # Get filter
        filter_expr = input("BPF Filter (e.g., 'tcp port 80' or 'host 192.168.1.1') [None]: ").strip()
        if not filter_expr:
            filter_expr = None
        
        # Get count
        count_input = input("Packet count [100]: ").strip()
        try:
            count = int(count_input) if count_input else DEFAULT_COUNT
        except ValueError:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid count: {count_input}")
            return
        
        # Get timeout
        timeout_input = input("Timeout (seconds) [None]: ").strip()
        try:
            timeout = int(timeout_input) if timeout_input else None
        except ValueError:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid timeout: {timeout_input}")
            return
        
        # Get output file
        output_file = input("Output PCAP file [None]: ").strip()
        if not output_file:
            output_file = None
        
        # Get verbose
        verbose_input = input("Verbose output? (y/n) [n]: ").strip().lower()
        verbose = verbose_input in ['y', 'yes']
        
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting capture...")
        print(f"  Interface: {interface or 'default'}")
        print(f"  Filter: {filter_expr or 'None'}")
        print(f"  Count: {count}")
        print(f"  Timeout: {timeout or 'None'} seconds")
        print(f"  Output: {output_file or 'None'}")
        print(f"  Verbose: {verbose}")
        print()
        
        # Start capture
        try:
            packets = self.engine.start_capture(
                interface=interface,
                filter_expr=filter_expr,
                count=count,
                timeout=timeout,
                output_file=output_file,
                verbose=verbose
            )
            
            print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Capture complete!")
            print(f"  Packets captured: {len(packets)}")
            
            if packets:
                print(f"\n{Fore.CYAN}Quick Summary:{Style.RESET_ALL}")
                print(self.formatter.format_summary(self.engine.statistics))
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Capture interrupted by user.")
            self.engine.stop_capture()
    
    def interactive_load(self):
        """Load packets from PCAP file."""
        filename = input(f"{Fore.CYAN}Enter PCAP filename: {Style.RESET_ALL}").strip()
        
        if not filename:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No filename provided.")
            return
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {filename}")
            return
        
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Loading {filename}...")
        
        try:
            packets = self.engine.load_from_pcap(filename)
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Loaded {len(packets)} packets.")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to load: {e}")
    
    def interactive_analyze(self):
        """Analyze loaded packets."""
        if not self.engine.captured_packets:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No packets loaded. Capture or load packets first.")
            return
        
        print(f"\n{Fore.CYAN}Analyze Options{Style.RESET_ALL}")
        print("-" * 40)
        print(f"Total packets available: {len(self.engine.captured_packets)}")
        
        # Get options
        packet_id = input("Packet ID (or 'all' for all, 'table' for table view) [all]: ").strip()
        verbose_input = input("Verbose? (y/n) [n]: ").strip().lower()
        verbose = verbose_input in ['y', 'yes']
        
        if packet_id.lower() == 'table':
            print(f"\n{Fore.CYAN}Packet Table:{Style.RESET_ALL}")
            print(self.formatter.format_table(self.engine.captured_packets))
        
        elif packet_id.lower() == 'all':
            for i, packet in enumerate(self.engine.captured_packets, 1):
                print(f"\n{Fore.CYAN}Packet #{i}{Style.RESET_ALL}")
                print("-" * 40)
                print(self.formatter.format_packet(packet, verbose=verbose))
        
        else:
            try:
                idx = int(packet_id) - 1
                if 0 <= idx < len(self.engine.captured_packets):
                    packet = self.engine.captured_packets[idx]
                    print(f"\n{Fore.CYAN}Packet #{idx + 1}{Style.RESET_ALL}")
                    print("-" * 40)
                    print(self.formatter.format_packet(packet, verbose=verbose))
                else:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid packet ID: {packet_id}")
            except ValueError:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid packet ID: {packet_id}")
    
    def interactive_export(self):
        """Export captured data."""
        if not self.engine.captured_packets:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No packets to export. Capture or load packets first.")
            return
        
        print(f"\n{Fore.CYAN}Export Options{Style.RESET_ALL}")
        print("-" * 40)
        print(f"Packets to export: {len(self.engine.captured_packets)}")
        
        # Get format
        format_choice = input("Format (csv/json/report): ").strip().lower()
        
        if format_choice not in ['csv', 'json', 'report']:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid format: {format_choice}")
            return
        
        # Get filename
        filename = input(f"Output filename: ").strip()
        
        if not filename:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No filename provided.")
            return
        
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Exporting...")
        
        try:
            if format_choice == 'csv':
                success = self.exporter.export_to_csv(self.engine.captured_packets, filename)
            elif format_choice == 'json':
                success = self.exporter.export_to_json(self.engine.captured_packets, filename)
            else:  # report
                success = self.exporter.export_report(
                    self.engine.captured_packets,
                    self.engine.statistics,
                    filename
                )
            
            if success:
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Exported to {filename}")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Export failed.")
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Export error: {e}")
    
    def display_statistics(self):
        """Display capture statistics."""
        if not self.engine.statistics.total_packets:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No statistics available. Capture or load packets first.")
            return
        
        print(self.formatter.format_summary(self.engine.statistics))


# =============================================================================
# MAIN APPLICATION
# =============================================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog=NAME.lower(),
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {NAME.lower()} capture --interface eth0 --count 100
  {NAME.lower()} capture --filter "tcp port 80" --output web.pcap
  {NAME.lower()} analyze --file capture.pcap --verbose
  {NAME.lower()} interactive
  {NAME.lower()} --version

For more information, visit: https://github.com/yourusername/netsentry
"""
    )
    
    # Global options
    parser.add_argument(
        '--version', '-v',
        action='store_true',
        help='Show version and exit'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(
        dest='command',
        title='commands',
        description='Available commands'
    )
    
    # Capture command
    capture_parser = subparsers.add_parser(
        'capture',
        help='Capture network packets',
        description='Capture network packets with optional filtering'
    )
    capture_parser.add_argument(
        '--interface', '-i',
        type=str,
        default=None,
        help='Network interface to capture from (default: auto-detect)'
    )
    capture_parser.add_argument(
        '--filter', '-f',
        type=str,
        default=None,
        help='BPF filter expression (e.g., "tcp port 80")'
    )
    capture_parser.add_argument(
        '--count', '-c',
        type=int,
        default=None,
        help='Number of packets to capture'
    )
    capture_parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=None,
        help='Capture duration in seconds'
    )
    capture_parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='Output PCAP filename'
    )
    capture_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    capture_parser.add_argument(
        '--no-store',
        action='store_true',
        help='Do not store packets in memory (stream to disk only)'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze captured packets',
        description='Analyze packets from a capture or file'
    )
    analyze_parser.add_argument(
        '--file', '-f',
        type=str,
        default=None,
        help='PCAP file to analyze'
    )
    analyze_parser.add_argument(
        '--packet', '-p',
        type=int,
        default=None,
        help='Specific packet ID to display'
    )
    analyze_parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Display all packets'
    )
    analyze_parser.add_argument(
        '--table', '-t',
        action='store_true',
        help='Display as table'
    )
    analyze_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    analyze_parser.add_argument(
        '--stats', '-s',
        action='store_true',
        help='Show statistics summary'
    )
    
    # Export command
    export_parser = subparsers.add_parser(
        'export',
        help='Export captured data',
        description='Export packets to various formats'
    )
    export_parser.add_argument(
        '--file', '-f',
        type=str,
        required=True,
        help='Input PCAP file (or use last capture)'
    )
    export_parser.add_argument(
        '--format', '-F',
        choices=['csv', 'json', 'report'],
        default='csv',
        help='Output format'
    )
    export_parser.add_argument(
        '--output', '-o',
        type=str,
        required=True,
        help='Output filename'
    )
    
    # Interactive command
    subparsers.add_parser(
        'interactive',
        help='Start interactive mode',
        description='Start the interactive command-line interface'
    )
    
    # List interfaces command
    subparsers.add_parser(
        'interfaces',
        help='List available network interfaces',
        description='Display all available network interfaces'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Show version
    if args.version:
        print(f"{NAME} v{VERSION}")
        print(f"Author: {AUTHOR}")
        print(f"Description: {DESCRIPTION}")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Scapy: {'Available' if SCAPY_AVAILABLE else 'Not Available'}")
        sys.exit(0)
    
    # Configure logging level
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Initialize components
    engine = PacketCaptureEngine()
    formatter = OutputFormatter(use_color=not args.no_color)
    exporter = DataExporter()
    
    try:
        # Handle commands
        if args.command is None or args.command == 'interactive':
            # Interactive mode
            interactive = InteractiveMode()
            interactive.run()
            
        elif args.command == 'interfaces':
            # List interfaces
            print(f"{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
            print("-" * 40)
            interfaces = get_available_interfaces()
            default = get_default_interface()
            for iface in interfaces:
                marker = " *" if iface == default else ""
                try:
                    addr = get_if_addr(iface)
                    print(f"  {iface}{marker}: {addr}")
                except:
                    print(f"  {iface}{marker}: <no address>")
            
        elif args.command == 'capture':
            # Capture packets
            require_privileges()
            
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting capture...")
            
            packets = engine.start_capture(
                interface=args.interface,
                filter_expr=args.filter,
                count=args.count,
                timeout=args.timeout,
                output_file=args.output,
                store_packets=not args.no_store,
                verbose=args.verbose
            )
            
            print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Capture complete!")
            print(f"  Packets captured: {len(packets)}")
            
            if args.verbose or args.stats:
                print(formatter.format_summary(engine.statistics))
            
            if args.table and packets:
                print(f"\n{Fore.CYAN}Packet Summary:{Style.RESET_ALL}")
                print(formatter.format_table(packets))
                
        elif args.command == 'analyze':
            # Analyze packets
            packets = []
            
            if args.file:
                if not os.path.exists(args.file):
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {args.file}")
                    sys.exit(1)
                packets = engine.load_from_pcap(args.file)
            elif engine.captured_packets:
                packets = engine.captured_packets
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No packets to analyze. Use --file or capture first.")
                sys.exit(1)
            
            if args.stats:
                print(formatter.format_summary(engine.statistics))
            
            elif args.table:
                print(formatter.format_table(packets))
            
            elif args.packet:
                if 1 <= args.packet <= len(packets):
                    packet = packets[args.packet - 1]
                    print(formatter.format_packet(packet, verbose=args.verbose))
                else:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid packet ID: {args.packet}")
                    sys.exit(1)
            
            elif args.all:
                for i, packet in enumerate(packets, 1):
                    print(f"\n{Fore.CYAN}Packet #{i}{Style.RESET_ALL}")
                    print("-" * 40)
                    print(formatter.format_packet(packet, verbose=args.verbose))
            
            else:
                # Default: show summary
                print(formatter.format_summary(engine.statistics))
                print(f"\n{Fore.CYAN}Use --all to see all packets, --table for table view, or --packet N for specific packet.{Style.RESET_ALL}")
                
        elif args.command == 'export':
            # Export data
            packets = []
            
            if args.file:
                if not os.path.exists(args.file):
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {args.file}")
                    sys.exit(1)
                # Create a temporary engine to load the file
                temp_engine = PacketCaptureEngine()
                packets = temp_engine.load_from_pcap(args.file)
                statistics = temp_engine.statistics
            elif engine.captured_packets:
                packets = engine.captured_packets
                statistics = engine.statistics
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No packets to export.")
                sys.exit(1)
            
            if args.format == 'csv':
                success = exporter.export_to_csv(packets, args.output)
            elif args.format == 'json':
                success = exporter.export_to_json(packets, args.output)
            else:  # report
                success = exporter.export_report(packets, statistics, args.output)
            
            if success:
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Exported {len(packets)} packets to {args.output}")
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Export failed.")
                sys.exit(1)
        
        else:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Unknown command: {args.command}")
            print("Use --help for available commands.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()