"""
NetSentry - Filter Examples
=============================

This example demonstrates various packet capture filters.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentry import PacketCaptureEngine, OutputFormatter, get_available_interfaces, get_default_interface


def example_tcp_only():
    """Capture TCP traffic only."""
    print("\n" + "=" * 60)
    print("Example 1: TCP Traffic Only")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"Capturing TCP traffic on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="tcp",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def example_port_80():
    """Capture HTTP traffic (port 80)."""
    print("\n" + "=" * 60)
    print("Example 2: HTTP Traffic (Port 80)")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"Capturing HTTP traffic on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="port 80",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def example_dns():
    """Capture DNS traffic (port 53)."""
    print("\n" + "=" * 60)
    print("Example 3: DNS Traffic (Port 53)")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"Capturing DNS traffic on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="port 53",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def example_icmp():
    """Capture ICMP traffic (ping)."""
    print("\n" + "=" * 60)
    print("Example 4: ICMP Traffic (Ping)")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"Capturing ICMP traffic on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="icmp",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def example_specific_host():
    """Capture traffic to/from specific host."""
    print("\n" + "=" * 60)
    print("Example 5: Specific Host (8.8.8.8)")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    # Note: 8.8.8.8 is Google DNS
    print(f"Capturing traffic to/from 8.8.8.8 on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="host 8.8.8.8",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def example_complex_filter():
    """Capture traffic with complex filter."""
    print("\n" + "=" * 60)
    print("Example 6: Complex Filter (TCP port 443)")
    print("=" * 60)
    
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"Capturing HTTPS traffic (tcp port 443) on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        filter_expr="tcp port 443",
        count=20,
        timeout=15
    )
    
    formatter = OutputFormatter()
    if packets:
        print(formatter.format_table(packets))


def main():
    """Run all examples."""
    print(f"\n{60 * '='}")
    print("NetSentry - Filter Examples")
    print(f"{60 * '='}")
    
    print("\nNote: Run with administrator/root privileges!")
    print("Some examples may not capture traffic if none is available")
    
    # Run examples
    try:
        example_tcp_only()
        example_port_80()
        example_dns()
        example_icmp()
        example_specific_host()
        example_complex_filter()
    except KeyboardInterrupt:
        print("\nInterrupted by user")


if __name__ == "__main__":
    main()
