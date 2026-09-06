"""PyNIDS test-suite (pytest).

Run:  python -m pytest tests/ -v

All tests are offline: synthetic PacketMeta objects or generated pcaps,
no admin rights and no live interface required.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from nids.alert_store import AlertStore           # noqa: E402
from nids.config import load_config               # noqa: E402
from nids.detectors.arp_spoof import ARPSpoofDetector       # noqa: E402
from nids.detectors.brute_force import BruteForceDetector   # noqa: E402
from nids.detectors.dns_tunnel import DNSTunnelDetector     # noqa: E402
from nids.detectors.dos_flood import DoSDetector            # noqa: E402
from nids.detectors.port_scan import PortScanDetector       # noqa: E402
from nids.detectors.web_attack import WebAttackDetector     # noqa: E402
from nids.engine import NidsEngine                # noqa: E402
from nids.packets import PacketMeta               # noqa: E402
from nids.response import ResponseEngine          # noqa: E402
from nids.rule_engine import RuleEngine           # noqa: E402


@pytest.fixture()
def config(tmp_path):
    cfg = load_config(PROJECT_ROOT / "config" / "nids_config.yaml", base_dir=PROJECT_ROOT)
    cfg["general"]["db_path"] = str(tmp_path / "test.db")
    cfg["general"]["alerts_jsonl"] = ""
    return cfg


def meta(**kwargs) -> PacketMeta:
    defaults = dict(timestamp=time.time(), src_ip="10.9.9.10", dst_ip="192.168.1.10",
                    protocol="TCP")
    defaults.update(kwargs)
    return PacketMeta(**defaults)


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class TestRuleEngine:

    def test_loads_shipped_rules(self, config):
        engine = RuleEngine(config)
        assert engine.load_rules() >= 25

    def test_content_match_in_uri(self, config):
        engine = RuleEngine(config)
        engine.load_rules()
        pkt = meta(dst_port=80,
                   payload=b"GET /x?id=1 UNION SELECT * FROM users HTTP/1.1\r\n\r\n")
        names = [a.name for a in engine.match_packet(pkt)]
        assert any("UNION SELECT" in n for n in names)

    def test_nocase_and_hex_content(self, config):
        engine = engine_for_rule(config,
            'alert tcp any any -> any 445 (msg:"SMB probe"; '
            'content:"|ff|SMB"; offset:4; depth:8; sid:99999; rev:1;)')
        pkt = meta(dst_port=445, payload=b"\x00\x00\x00\x54\xffSMBr\x00\x00")
        assert [a.name for a in engine.match_packet(pkt)] == ["SMB probe"]

    def test_flags_match(self, config):
        engine = engine_for_rule(config,
            'alert tcp any any -> any 80 (msg:"syn only"; flags:S; sid:99998; rev:1;)')
        assert engine.match_packet(meta(dst_port=80, tcp_flags="S"))
        assert not engine.match_packet(meta(dst_port=80, tcp_flags="SA"))

    def test_detection_filter_window(self, config):
        engine = engine_for_rule(config,
            'alert tcp any any -> any 22 (msg:"burst"; flags:S; '
            'detection_filter:track by_src, count 5, seconds 60; sid:99997; rev:1;)')
        packets = [meta(timestamp=1000 + i, dst_port=22, tcp_flags="S") for i in range(5)]
        fired = [bool(engine.match_packet(p)) for p in packets]
        assert fired == [False, False, False, False, True]

    def test_home_net_variable(self, config):
        engine = engine_for_rule(config,
            'alert tcp any any -> $HOME_NET 80 (msg:"home"; sid:99996; rev:1;)')
        assert engine.match_packet(meta(dst_ip="192.168.1.55", dst_port=80))
        assert not engine.match_packet(meta(dst_ip="8.8.8.8", dst_port=80))

    def test_bidirectional(self, config):
        engine = engine_for_rule(config,
            'alert tcp $HOME_NET any <> any 23 (msg:"telnet"; flags:S; sid:99995; rev:1;)')
        assert engine.match_packet(meta(src_ip="192.168.1.5", dst_port=23, tcp_flags="S"))
        assert engine.match_packet(meta(src_ip="1.2.3.4", src_port=23,
                                        dst_ip="192.168.1.5", tcp_flags="S"))


def engine_for_rule(config, rule_text: str, tmp=None) -> RuleEngine:
    import tempfile
    tmp = tmp or tempfile.mkdtemp(prefix="nids_rule_")
    rule_path = Path(tmp) / "single.rules"
    rule_path.write_text(rule_text, encoding="utf-8")
    engine = RuleEngine(config)
    engine.load_rules(str(rule_path))
    return engine


# ---------------------------------------------------------------------------
# Behavioural detectors
# ---------------------------------------------------------------------------


class TestDetectors:

    def test_port_scan(self):
        det = PortScanDetector(load_config(None))
        t0 = 1000.0
        alerts = []
        for i in range(12):
            alerts += det.process(meta(timestamp=t0 + i * 0.2, dst_port=1000 + i,
                                       tcp_flags="S"))
        assert alerts and "PORT SCAN" in alerts[0].name
        assert alerts[0].severity >= 2

    def test_stealth_scan(self):
        det = PortScanDetector(load_config(None))
        t0 = 1000.0
        alerts = []
        for i in range(13):
            alerts += det.process(meta(timestamp=t0 + i * 0.2, dst_port=2000 + i,
                                       tcp_flags="F"))
        assert any("stealth" in a.name for a in alerts)

    def test_no_scan_false_positive(self):
        det = PortScanDetector(load_config(None))
        alerts = []
        for i in range(6):
            alerts += det.process(meta(timestamp=1000 + i, dst_port=443 + i * 1000,
                                       tcp_flags="S"))
        assert not alerts

    def test_brute_force_ssh(self):
        det = BruteForceDetector(load_config(None))
        t0 = 2000.0
        alerts = []
        for i in range(8):
            alerts += det.process(meta(timestamp=t0 + i * 0.5, dst_port=22,
                                       tcp_flags="S"))
        assert alerts and "SSH" in alerts[0].name and alerts[0].severity == 3

    def test_http_auth_failure(self):
        det = BruteForceDetector(load_config(None))
        t0 = 3000.0
        alerts = []
        for i in range(10):
            alerts += det.process(meta(timestamp=t0 + i * 0.5,
                                       src_ip="192.168.1.10", dst_ip="10.9.9.5",
                                       dst_port=41000,
                                       http={"is_request": False, "status": 401,
                                             "body": "", "headers": {}}))
        assert alerts and "HTTP auth failures" in alerts[0].name

    def test_syn_flood(self):
        det = DoSDetector(load_config(None))
        t0 = 4000.0
        alerts = []
        for i in range(100):
            alerts += det.process(meta(timestamp=t0 + i * 0.05, dst_port=80,
                                       tcp_flags="S"))
        assert alerts and "SYN flood" in alerts[0].name

    def test_icmp_flood(self):
        det = DoSDetector(load_config(None))
        alerts = []
        for i in range(60):
            alerts += det.process(meta(timestamp=5000 + i * 0.1, protocol="ICMP",
                                       icmp_type=8))
        assert alerts and "ICMP" in alerts[0].name

    def test_arp_spoof(self):
        det = ARPSpoofDetector({"detectors": {"arp_spoof": {
            "enabled": True, "gateways": ["192.168.1.1"], "cooldown_seconds": 0}}})
        first = det.process(meta(timestamp=1.0, protocol="ARP", arp_op=2,
                                 arp_sender_ip="192.168.1.1",
                                 arp_sender_mac="00:1a:2b:3c:4d:5e"))
        assert not first
        poison = det.process(meta(timestamp=2.0, protocol="ARP", arp_op=2,
                                  arp_sender_ip="192.168.1.1",
                                  arp_sender_mac="de:ad:be:ef:13:37"))
        assert poison and poison[0].severity == 4   # gateway hijack

    def test_dns_tunnel_length(self):
        det = DNSTunnelDetector(load_config(None))
        alert = det.process(meta(timestamp=10.0, protocol="DNS", dns_is_response=False,
                                 dst_port=53,
                                 dns_qname="a" * 60 + ".evil.net"))
        assert alert and "tunnelling" in alert[0].name

    def test_dns_tunnel_rate(self):
        det = DNSTunnelDetector(load_config(None))
        alerts = []
        for i in range(40):
            alerts += det.process(meta(timestamp=20.0 + i * 0.2, protocol="DNS",
                                       dns_is_response=False, dst_port=53,
                                       dns_qname=f"host{i}.example.com"))
        assert any("abnormal DNS query rate" in a.name for a in alerts)

    def test_web_attack_sqli(self):
        det = WebAttackDetector(load_config(None))
        alerts = det.process(meta(dst_port=80,
                                  http={"is_request": True, "method": "GET",
                                        "path": "/p?id=1' OR '1'='1",
                                        "body": "", "headers": {}, "user_agent": "x"}))
        assert alerts and "SQL injection" in alerts[0].name

    def test_web_attack_log4shell_critical(self):
        det = WebAttackDetector(load_config(None))
        payload = "${" + "j" + "ndi:ldap://x/y}"
        alerts = det.process(meta(dst_port=8080,
                                  http={"is_request": True, "method": "GET",
                                        "path": "/", "body": "",
                                        "headers": {}, "user_agent": payload}))
        assert alerts and alerts[0].severity == 4

    def test_url_encoding_evasion(self):
        det = WebAttackDetector(load_config(None))
        alerts = det.process(meta(dst_port=80,
                                  http={"is_request": True, "method": "GET",
                                        "path": "/x?q=%3C%73%63%72%69%70%74%3E",
                                        "body": "", "headers": {}, "user_agent": ""}))
        assert alerts and "XSS" in alerts[0].name


# ---------------------------------------------------------------------------
# Response engine
# ---------------------------------------------------------------------------


class TestResponse:

    def _response(self, config, store, **overrides):
        cfg = dict(config)
        cfg["response"] = dict(config["response"], **overrides)
        return ResponseEngine(cfg, store)

    def test_immediate_block_on_critical(self, config, tmp_path):
        store = AlertStore(tmp_path / "r1.db")
        resp = self._response(config, store)
        from nids.alert import Alert
        critical = Alert(timestamp=time.time(), name="log4shell", severity=4,
                         detector="web_attack", src_ip="10.9.9.99")
        resp.handle(critical)
        assert store.is_blocked("10.9.9.99")
        assert critical.action == "blocked"

    def test_escalation_block(self, config, tmp_path):
        store = AlertStore(tmp_path / "r2.db")
        resp = self._response(config, store)
        from nids.alert import Alert
        t0 = time.time()
        for i in range(4):
            alert = Alert(timestamp=t0 + i * 10, name=f"high alert {i}",
                          severity=3, detector="brute_force", src_ip="10.9.9.100")
            resp.handle(alert)
        assert store.is_blocked("10.9.9.100")

    def test_low_severity_never_blocks(self, config, tmp_path):
        store = AlertStore(tmp_path / "r3.db")
        resp = self._response(config, store)
        from nids.alert import Alert
        for i in range(20):
            resp.handle(Alert(timestamp=time.time() + i, name="low", severity=1,
                              detector="policy", src_ip="10.9.9.101"))
        assert not store.is_blocked("10.9.9.101")

    def test_whitelist_blocks_active_mode(self, config, tmp_path):
        store = AlertStore(tmp_path / "r4.db")
        cfg = dict(config)
        cfg["general"] = dict(config["general"], whitelist_ips=["127.0.0.1"])
        cfg["response"] = dict(config["response"], mode="active")
        resp = ResponseEngine(cfg, store)
        from nids.alert import Alert
        resp.handle(Alert(timestamp=time.time(), name="crit on loopback",
                          severity=4, detector="test", src_ip="127.0.0.1"))
        # recorded, but flagged as simulated because the IP is whitelisted
        blocks = store.active_blocks()
        assert len(blocks) == 1 and blocks[0]["mode"] == "simulate"

    def test_manual_block_unblock(self, config, tmp_path):
        store = AlertStore(tmp_path / "r5.db")
        resp = ResponseEngine(config, store)
        created, mode = resp.manual_block("10.9.9.102", reason="test")
        assert created and store.is_blocked("10.9.9.102")
        assert resp.manual_unblock("10.9.9.102")
        assert not store.is_blocked("10.9.9.102")


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class TestStore:

    def test_roundtrip(self, tmp_path):
        from nids.alert import Alert
        store = AlertStore(tmp_path / "s.db")
        alert = Alert(timestamp=1700000000.0, name="test alert", severity=3,
                      category="Web Attack", detector="web_attack", protocol="TCP",
                      src_ip="10.9.9.1", src_port=5, dst_ip="192.168.1.2", dst_port=80,
                      details="d")
        saved = store.save_alert(alert)
        assert saved.alert_id is not None
        rows = store.recent_alerts(limit=10)
        assert len(rows) == 1
        assert rows[0].name == "test alert" and rows[0].severity == 3

    def test_export_csv(self, tmp_path):
        from nids.alert import Alert
        store = AlertStore(tmp_path / "s2.db")
        store.save_alert(Alert(name="a", severity=2))
        out = tmp_path / "out.csv"
        assert store.export_csv(out) == 1
        assert "severity" in out.read_text(encoding="utf-8").splitlines()[0]

    def test_timeseries_buckets(self, tmp_path):
        from nids.alert import Alert
        store = AlertStore(tmp_path / "s3.db")
        now = time.time()
        store.save_alert(Alert(timestamp=now, name="x", severity=1))
        series = store.timeseries(minutes=5, bucket_seconds=60)
        assert sum(s["count"] for s in series) >= 1

    def test_block_ttl_expiry(self, tmp_path):
        store = AlertStore(tmp_path / "s4.db")
        store.save_block("10.9.9.103", reason="t", mode="simulate", ttl_seconds=-1)
        assert store.expire_old_blocks() >= 1
        assert not store.is_blocked("10.9.9.103")


# ---------------------------------------------------------------------------
# Integration: full engine over the generated demo pcap
# ---------------------------------------------------------------------------


class TestIntegration:

    @pytest.fixture(scope="class")
    def pcap(self, tmp_path_factory):
        from tools.generate_demo_pcap import generate_demo_pcap
        return generate_demo_pcap(tmp_path_factory.mktemp("pcap") / "demo.pcap",
                                  compact=True)

    def test_full_pipeline(self, config, pcap):
        engine = NidsEngine(config)
        summary = engine.run_pcap(str(pcap))
        names = " | ".join(a.name for a in engine.store.recent_alerts(limit=2000))

        assert summary["packets"] > 400
        for expected in ("PORT SCAN", "BRUTE FORCE", "DOS", "EXFIL",
                         "ARP SPOOFING", "WEB ATTACK", "MALWARE"):
            assert expected in names, f"missing detection family: {expected}"

        stats = engine.store.stats()
        assert stats["by_severity"].get(4, 0) >= 1          # critical detections
        assert len(stats["top_sources"]) >= 4               # multiple attackers
        blocks = {b["ip"] for b in engine.store.active_blocks()}
        assert {"10.0.0.66", "10.0.0.77", "10.0.0.88"} & blocks  # response fired
