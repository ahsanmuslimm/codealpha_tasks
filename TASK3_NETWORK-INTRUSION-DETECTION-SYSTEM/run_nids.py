#!/usr/bin/env python3
"""PyNIDS - Network Intrusion Detection System (CodeAlpha TASK3).

Main command-line entry point.

Typical usage
-------------
    python run_nids.py --generate-demo-pcap              # build demo traffic
    python run_nids.py --pcap demo/demo_traffic.pcap     # offline detection
    python run_nids.py --replay-live demo/demo_traffic.pcap   # live-style demo
    python run_nids.py --interface "Wi-Fi"               # real monitoring
    python run_nids.py --dashboard                       # SOC dashboard
    python run_nids.py --simulate-attacks                # fire attacks at 127.0.0.1
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from nids import __version__, PRODUCT  # noqa: E402
from nids.config import load_config  # noqa: E402
from nids.utils import BRIGHT_CYAN, BOLD, enable_ansi, paint, ts_to_iso  # noqa: E402

logger = logging.getLogger("nids.cli")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def banner() -> None:
    print(paint(r"""
  ==============================================================
     N E T W O R K   I N T R U S I O N   D E T E C T I O N
     S Y S T E M   -   PyNIDS v{version}  (CodeAlpha TASK3)
  ==============================================================
""".replace("{version}", __version__), BRIGHT_CYAN + BOLD))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_nids.py",
        description=f"{PRODUCT} - detection engine, response automation and dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Typical usage")[1] if __doc__ else None,
    )
    parser.add_argument("--version", action="version", version=f"PyNIDS {__version__}")
    parser.add_argument("--config", help="path to YAML config (default: config/nids_config.yaml)")

    modes = parser.add_argument_group("mode (pick one)")
    modes.add_argument("--pcap", metavar="FILE", help="offline detection on a pcap file")
    modes.add_argument("--replay-live", metavar="FILE", dest="replay_live",
                       help="replay a pcap paced in real time (live-style demo)")
    modes.add_argument("--interface", metavar="IFACE", help="live monitoring on an interface")
    modes.add_argument("--simulate-attacks", action="store_true",
                       help="fire a scripted attack burst at a target (default 127.0.0.1)")
    modes.add_argument("--generate-demo-pcap", action="store_true", dest="generate_demo_pcap",
                       help="generate demo/demo_traffic.pcap containing a full attack scenario")
    modes.add_argument("--dashboard", action="store_true", help="run the web dashboard")
    modes.add_argument("--service", action="store_true",
                       help="continuous EVE-log monitoring mode (real Suricata feeds)")

    extras = parser.add_argument_group("utilities")
    extras.add_argument("--list-interfaces", action="store_true", dest="list_interfaces",
                        help="list capture-capable network interfaces")
    extras.add_argument("--stats", action="store_true", help="print alert database statistics")
    extras.add_argument("--export-csv", metavar="PATH", dest="export_csv",
                        help="export all alerts to CSV")
    extras.add_argument("--report", action="store_true",
                        help="generate Markdown + CSV incident report from the alert DB")
    extras.add_argument("--block", metavar="IP", help="manually block an IP")
    extras.add_argument("--unblock", metavar="IP", help="manually unblock an IP")
    extras.add_argument("--show-blocked", action="store_true", dest="show_blocked",
                        help="list currently blocked IPs")
    extras.add_argument("--import-eve", metavar="FILE", dest="import_eve",
                        help="import Suricata EVE JSON alerts into the alert DB")
    extras.add_argument("--selftest", action="store_true",
                        help="run the built-in engine self-test (no privileges needed)")

    settings = parser.add_argument_group("settings")
    settings.add_argument("--db", help="override alert database path")
    settings.add_argument("--rules", help="override rules file path")
    settings.add_argument("--target", default="127.0.0.1",
                          help="target for --simulate-attacks (default 127.0.0.1)")
    settings.add_argument("--speed", type=float, default=None,
                          help="replay speed multiplier (default from config)")
    settings.add_argument("--quiet", action="store_true", help="suppress per-alert console output")
    settings.add_argument("--verbose", action="store_true", help="debug logging")
    return parser


def load_runtime_config(args: argparse.Namespace) -> dict:
    overrides: dict = {}
    if args.db:
        overrides["general"] = {"db_path": args.db}
    if args.rules:
        overrides.setdefault("rules", {})["file"] = args.rules
    return load_config(args.config, overrides=overrides, base_dir=PROJECT_ROOT)


def setup_logging(config: dict, verbose: bool = False) -> None:
    level = "DEBUG" if verbose else config["general"].get("log_level", "INFO")
    log_dir = PROJECT_ROOT / "data"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stderr),
            logging.FileHandler(log_dir / "nids.log", encoding="utf-8"),
        ],
    )


def build_engine(config: dict, quiet: bool):
    from nids.engine import NidsEngine
    engine = NidsEngine(config)
    if not quiet:
        original = engine._print_alert

        def print_alert(alert):
            original(alert)

        engine.on_alert = print_alert
    return engine


def print_summary(summary: dict) -> None:
    print(paint("\n  ---- SESSION SUMMARY " + "-" * 42, BOLD))
    print(f"  Source          : {summary.get('source', '-')}")
    print(f"  Packets         : {summary.get('packets', 0):,}")
    print(f"  Alerts          : {summary.get('alerts', 0):,}")
    by_sev = summary.get("by_severity", {})
    if by_sev:
        names = {"4": "critical", "3": "high", "2": "medium", "1": "low"}
        sev_str = ", ".join(f"{names.get(k, k)}={v}" for k, v in by_sev.items())
        print(f"  By severity     : {sev_str}")
    by_det = summary.get("by_detector", {})
    if by_det:
        det_str = ", ".join(f"{k}={v}" for k, v in sorted(by_det.items(), key=lambda x: -x[1]))
        print(f"  By detector     : {det_str}")
    blocks = summary.get("blocks", {})
    if blocks:
        print(f"  Response blocks : {blocks.get('blocks_executed', 0)} active, "
              f"{blocks.get('blocks_simulated', 0)} simulated")
    print(paint("  " + "-" * 63, BOLD))


# ---------------------------------------------------------------------------
# Mode implementations
# ---------------------------------------------------------------------------


def mode_pcap(engine, path: str) -> None:
    print(paint(f"\n[*] Offline detection on {path}", BOLD))
    summary = engine.run_pcap(path, verbose=True)
    print_summary(summary)


def mode_replay(engine, path: str, speed: float) -> None:
    print(paint(f"\n[*] Live-style replay of {path} at {speed:.0f}x "
                "(alerts appear as they would in real time)", BOLD))
    summary = engine.run_replay(path, speed=speed)
    print_summary(summary)


def mode_live(engine, interface: str, config: dict) -> None:
    bpf = config.get("capture", {}).get("bpf_filter", "")
    promisc = bool(config.get("capture", {}).get("promisc", True))
    print(paint(f"\n[*] Continuous monitoring on '{interface}'"
                + (f" (BPF: {bpf})" if bpf else "") + " - press Ctrl-C to stop", BOLD))
    summary = engine.run_live(interface, bpf_filter=bpf, promisc=promisc)
    print_summary(summary)


def mode_dashboard(config: dict, args) -> None:
    from dashboard.app import run_dashboard
    run_dashboard(config, host=args.host, port=args.port)


def mode_simulate_attacks(config: dict, target: str) -> None:
    from tools.attack_simulator import run_all_attacks
    run_all_attacks(target=target)


def mode_stats(config: dict) -> None:
    from nids.alert_store import AlertStore
    store = AlertStore(config["general"]["db_path"])
    stats = store.stats()
    status = store.engine_status()
    print(paint("\n  ALERT DATABASE STATISTICS", BOLD))
    print(f"  Database        : {config['general']['db_path']}")
    engine_state = (f"RUNNING ({status.get('info', '')})"
                    if status.get("running") else "not currently running")
    print(f"  Engine          : {engine_state}")
    print(f"  Total alerts    : {stats['total_alerts']:,}")
    print(f"  Unique sources  : {stats['unique_sources']}")
    sev = stats["by_severity"]
    print(f"  Critical/High   : {sev.get(4, 0)} / {sev.get(3, 0)}")
    print("  By category:")
    for row in stats["by_category"][:10]:
        print(f"    {row['category']:22s} {row['count']:>6,}")
    print("  Top sources:")
    for row in stats["top_sources"][:10]:
        print(f"    {row['ip']:22s} {row['count']:>6,} alerts (max sev {row['max_severity']})")
    blocks = store.active_blocks()
    print(f"  Blocked IPs     : {len(blocks)}")
    for b in blocks:
        print(f"    {b['ip']:22s} {b['mode']:9s} until {b['expires']}")


def mode_report(config: dict) -> None:
    from tools.export_report import generate_report
    paths = generate_report(config)
    print(paint("\n[*] Incident report generated:", BOLD))
    for p in paths:
        print(f"    {p}")


def mode_import_eve(config: dict, path: str) -> None:
    from tools.import_eve import import_eve_file
    count = import_eve_file(config, path)
    print(f"[*] Imported {count} EVE alert(s) from {path}")


def mode_interfaces() -> None:
    from nids.packet_capture import list_interfaces
    print(paint("\n  CAPTURE-CAPABLE INTERFACES", BOLD))
    for iface in list_interfaces():
        print(f"    {iface['name']}")
        detail = f"      ip={iface['ip']}  mac={iface['mac']}"
        if iface["description"]:
            detail += f"\n      desc: {iface['description']}"
        print(detail)


def mode_blocked(config: dict) -> None:
    from nids.alert_store import AlertStore
    store = AlertStore(config["general"]["db_path"])
    blocks = store.active_blocks()
    if not blocks:
        print("[*] No IPs are currently blocked.")
        return
    print(paint(f"\n  BLOCKED IPs ({len(blocks)})", BOLD))
    for b in blocks:
        print(f"    {b['ip']:20s} mode={b['mode']:9s} since {b['created']}  "
              f"until {b['expires']}  reason: {b['reason']}")


def mode_block(config: dict, ip: str) -> None:
    from nids.alert_store import AlertStore
    from nids.response import ResponseEngine
    store = AlertStore(config["general"]["db_path"])
    response = ResponseEngine(config, store)
    created, mode = response.manual_block(ip, reason="manual block via run_nids.py")
    print(f"[*] {'Blocked' if created else 'Block refreshed for'} {ip} (mode={mode})")


def mode_unblock(config: dict, ip: str) -> None:
    from nids.alert_store import AlertStore
    from nids.response import ResponseEngine
    store = AlertStore(config["general"]["db_path"])
    response = ResponseEngine(config, store)
    lifted = response.manual_unblock(ip)
    print(f"[*] {'Unblocked' if lifted else 'No active block for'} {ip}")


def mode_selftest(config: dict) -> None:
    from tests.selftest import run_selftest
    ok = run_selftest(config)
    sys.exit(0 if ok else 1)


def mode_generate_demo() -> None:
    from tools.generate_demo_pcap import generate_demo_pcap
    path = generate_demo_pcap()
    print(f"[*] Demo traffic written to {path}")
    print("[*] Next: python run_nids.py --pcap \"" + str(path) + "\"")


def mode_service(config: dict, args) -> None:
    """Continuous EVE monitoring (for a real Suricata sensor) + dashboard."""
    from nids.alert_store import AlertStore
    from tools.import_eve import tail_eve
    eve_path = args.eve
    if not eve_path:
        print("[!] --service requires --eve <path-to-eve.json>")
        sys.exit(2)
    interval = args.interval
    print(paint(f"[*] Tailing Suricata EVE log {eve_path} every {interval}s "
                "(Ctrl-C to stop)", BOLD))
    store = AlertStore(config["general"]["db_path"])
    stop = threading.Event()
    if args.with_dashboard:
        from dashboard.app import start_dashboard_thread
        start_dashboard_thread(config)

        def beat():
            while not stop.wait(5):
                store.heartbeat("eve-tail")

        threading.Thread(target=beat, daemon=True).start()
    try:
        tail_eve(config, eve_path, interval=interval, stop_event=stop)
    except KeyboardInterrupt:
        pass


def add_service_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--eve", help="path to Suricata eve.json")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="EVE polling interval seconds")
    parser.add_argument("--with-dashboard", action="store_true", dest="with_dashboard",
                        help="also start the dashboard in a background thread")
    parser.add_argument("--host", help="dashboard bind host override")
    parser.add_argument("--port", type=int, help="dashboard port override")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    enable_ansi()
    parser = build_arg_parser()
    add_service_args(parser)
    args = parser.parse_args(argv)
    config = load_runtime_config(args)
    setup_logging(config, verbose=args.verbose)
    banner()

    if args.list_interfaces:
        mode_interfaces()
        return 0
    if args.generate_demo_pcap:
        mode_generate_demo()
        return 0
    if args.selftest:
        mode_selftest(config)
        return 0
    if args.stats:
        mode_stats(config)
        return 0
    if args.report:
        mode_report(config)
        return 0
    if args.show_blocked:
        mode_blocked(config)
        return 0
    if args.block:
        mode_block(config, args.block)
        return 0
    if args.unblock:
        mode_unblock(config, args.unblock)
        return 0
    if args.export_csv:
        from nids.alert_store import AlertStore
        store = AlertStore(config["general"]["db_path"])
        count = store.export_csv(args.export_csv)
        print(f"[*] Exported {count} alerts to {args.export_csv}")
        return 0
    if args.import_eve:
        mode_import_eve(config, args.import_eve)
        return 0

    if args.dashboard:
        mode_dashboard(config, args)
        return 0
    if args.service:
        mode_service(config, args)
        return 0
    if args.simulate_attacks:
        mode_simulate_attacks(config, args.target)
        return 0

    engine = build_engine(config, quiet=args.quiet)

    if args.pcap:
        mode_pcap(engine, args.pcap)
        return 0
    if args.replay_live:
        speed = args.speed or float(config.get("capture", {}).get("replay_speed", 10.0))
        mode_replay(engine, args.replay_live, speed)
        return 0
    if args.interface:
        from nids.packet_capture import SCAPY_AVAILABLE
        if not SCAPY_AVAILABLE:
            print("[!] scapy is not installed - live capture unavailable")
            return 1
        mode_live(engine, args.interface, config)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
