"""Unit tests for NetSentry models."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import datetime
from netsentry.models import PacketInfo, Statistics, Filter


def test_packet_info_creation():
    """Test PacketInfo creation."""
    packet = PacketInfo(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol="TCP",
        src_port=54321,
        dst_port=80
    )
    assert packet.src_ip == "192.168.1.1"
    assert packet.dst_ip == "8.8.8.8"
    assert packet.protocol == "TCP"
    assert packet.timestamp is not None


def test_filter_to_bpf():
    """Test filter BPF generation."""
    filter_obj = Filter("port", 80)
    bpf = filter_obj.to_bpf()
    assert "port 80" in bpf


def test_statistics_update():
    """Test statistics update."""
    stats = Statistics()
    packet = PacketInfo(
        protocol="TCP",
        packet_length=100,
        src_ip="192.168.1.1"
    )
    stats.update(packet)
    assert stats.total_packets == 1
    assert stats.total_bytes == 100


if __name__ == "__main__":
    test_packet_info_creation()
    test_filter_to_bpf()
    test_statistics_update()
    print("✓ All tests passed!")
