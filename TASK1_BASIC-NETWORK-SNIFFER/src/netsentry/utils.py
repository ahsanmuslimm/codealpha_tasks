"""Utility functions for NetSentry."""

import os
import sys
import re
import socket
import platform
import ctypes
import logging
from typing import Optional, List, Union

try:
    from scapy.all import get_if_list
except ImportError:
    def get_if_list(): return []

logger = logging.getLogger(__name__)


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
    from colorama import Fore, Style
    
    if not check_privileges():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} NetSentry requires administrative/root privileges.")
        print("Please run with:")
        if platform.system() == 'Windows':
            print("  - Right-click Command Prompt and 'Run as Administrator'")
        else:
            print("  - sudo python3 netsentry")
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
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
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
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    if 8000 <= port <= 8999:
        return 'HTTP-ALT'
    if 9000 <= port <= 9999:
        return 'CUSTOM'
    return 'UNKNOWN'


def mask_sensitive_data(payload: bytes) -> bytes:
    """Mask sensitive data in payload."""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
    except:
        return payload
    
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
