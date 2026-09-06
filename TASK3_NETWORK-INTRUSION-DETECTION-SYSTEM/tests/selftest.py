#!/usr/bin/env python3
"""Fast built-in engine self-test (no admin rights, no live capture needed).

Run via:  python run_nids.py --selftest
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import List

from nids.packets import PacketMeta


def _meta(**kwargs) -> PacketMeta:
    defaults = dict(timestamp=time.time(), src_ip="10.9.9.10", dst_ip="192.168.1.10",
                    protocol="TCP")
    defaults.update(kwargs)
    return PacketMeta(**defaults)


def run_selftest(config: dict) -> bool:
    """Exercise the whole pipeline with synthetic packets. Returns success."""
    print("[*] Running PyNIDS self-test...")
    results: List[tuple] = []

    def check(name: str, ok: bool) -> None:
        results.append((name, ok))
        print(f"    [{'PASS' if ok else 'FAIL'}] {name}")

    # 1. rules load
    from nids.rule_engine import RuleEngine
    engine_cfg = dict(config)
    tmpdir = tempfile.mkdtemp(prefix="nids_selftest_")
    engine_cfg["general"] = dict(config["general"])
    engine_cfg["general"]["db_path"] = str(Path(tmpdir) / "selftest.db")
    engine_cfg["general"]["alerts_jsonl"] = ""
    rules = RuleEngine(engine_cfg)
    loaded = rules.load_rules()
    check(f"signature rules loaded ({loaded})", loaded >= 25)

    # 2. rule content match (SQLi in URI)
    sqli = _meta(src_ip="10.9.9.5", dst_ip="192.168.1.10", src_port=5, dst_port=80,
                 payload=b"GET /a?id=1 UNION SELECT * FROM users HTTP/1.1\r\n\r\n")
    hits = [a.name for a in rules.match_packet(sqli)]
    check("rule engine detects SQLi payload", any("UNION SELECT" in h for h in hits))

    # 3. full engine pipeline: port scan
    from nids.engine import NidsEngine
    engine = NidsEngine(engine_cfg)
    scan_alerts = []
    base = time.time()
    for i in range(15):  # >= detector threshold 12 distinct ports
        scan_alerts += engine.process_meta(_meta(
            timestamp=base + i * 0.2, src_ip="10.9.9.77", dst_port=1000 + i,
            tcp_flags="S"))
    check("port scan detector fires", any("PORT SCAN" in a.name for a in scan_alerts))

    # 4. brute force detector
    bf_alerts = []
    for i in range(10):  # >= threshold 8
        bf_alerts += engine.process_meta(_meta(
            timestamp=base + 30 + i * 0.3, src_ip="10.9.9.88", dst_port=22,
            tcp_flags="S"))
    check("brute force detector fires", any("BRUTE FORCE" in a.name for a in bf_alerts))

    # 5. response engine: trigger an immediate block via a critical-severity alert
    from nids.alert import Alert as AlertModel
    crit = AlertModel(timestamp=base + 60, name="WEB ATTACK: Log4Shell",
                      severity=4, detector="web_attack", src_ip="10.9.9.99")
    engine.response.handle(crit)
    check("response engine applied blocks", engine.store.is_blocked("10.9.9.99"))

    # 6. persistence round-trip
    stored = engine.store.recent_alerts(limit=500)
    check("alerts persisted to SQLite", len(stored) >= len(scan_alerts) + len(bf_alerts))

    # 7. CSV export
    csv_path = Path(tmpdir) / "export.csv"
    n = engine.store.export_csv(csv_path)
    check(f"CSV export ({n} rows)", csv_path.exists() and n > 0)

    # 8. stats + timeseries APIs
    stats = engine.store.stats()
    check("stats aggregation works", stats["total_alerts"] > 0
          and "by_severity" in stats)
    engine.store.heartbeat("selftest")
    check("engine heartbeat present", engine.store.engine_status()["running"])

    engine.store.close()
    ok = all(r for _, r in results)
    print(f"[*] Self-test {'PASSED' if ok else 'FAILED'} "
          f"({sum(r for _, r in results)}/{len(results)} checks)")
    return ok
