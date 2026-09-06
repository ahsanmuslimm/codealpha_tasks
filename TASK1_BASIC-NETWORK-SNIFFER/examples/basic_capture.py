"""
NetSentry - Basic Capture Example
===================================

This example demonstrates basic packet capture functionality.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentry import PacketCaptureEngine, OutputFormatter, get_available_interfaces


def main():
    """Basic capture example."""
    
    # List available interfaces
    interfaces = get_available_interfaces()
    if not interfaces:
        print("No network interfaces available")
        return
    
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")
    
    # Use first interface
    interface = interfaces[0]
    print(f"\nUsing interface: {interface}")
    
    # Create engine and start capture
    engine = PacketCaptureEngine()
    
    print("Capturing 50 packets...")
    packets = engine.start_capture(
        interface=interface,
        count=50,
        timeout=30,
        verbose=True
    )
    
    # Display results
    formatter = OutputFormatter()
    
    if packets:
        print("\n" + formatter.format_summary(engine.statistics))
        
        # Show first 5 packets
        print("\nFirst 5 packets in table format:")
        print(formatter.format_table(packets[:5]))


if __name__ == "__main__":
    main()
