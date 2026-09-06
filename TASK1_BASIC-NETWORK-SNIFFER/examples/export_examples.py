"""
NetSentry - Export Examples
=============================

This example demonstrates various export formats.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsentry import PacketCaptureEngine, DataExporter, get_default_interface


def main():
    """Export examples."""
    
    print("\n" + "=" * 60)
    print("NetSentry - Export Examples")
    print("=" * 60)
    
    # Capture some packets
    engine = PacketCaptureEngine()
    interface = get_default_interface()
    
    print(f"\nCapturing packets on {interface}...")
    packets = engine.start_capture(
        interface=interface,
        count=100,
        timeout=30,
        verbose=False
    )
    
    if not packets:
        print("No packets captured")
        return
    
    print(f"Captured {len(packets)} packets")
    
    # Export examples
    print("\n" + "=" * 60)
    print("Exporting to different formats...")
    print("=" * 60)
    
    # Export to CSV
    print("\n1. Exporting to CSV...")
    csv_file = "capture.csv"
    if DataExporter.export_to_csv(packets, csv_file):
        print(f"   Successfully exported to {csv_file}")
        print(f"   You can open this in Excel or any text editor")
    
    # Export to JSON
    print("\n2. Exporting to JSON...")
    json_file = "capture.json"
    if DataExporter.export_to_json(packets, json_file):
        print(f"   Successfully exported to {json_file}")
        print(f"   You can open this in any text editor or JSON viewer")
    
    # Export to HTML Report
    print("\n3. Exporting to HTML Report...")
    html_file = "capture_report.html"
    if DataExporter.export_to_html(packets, engine.statistics, html_file):
        print(f"   Successfully exported to {html_file}")
        print(f"   You can open this in any web browser")
    
    print("\n" + "=" * 60)
    print("All exports completed!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
