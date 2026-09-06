#!/usr/bin/env python3
"""Generate a Markdown + CSV incident report from the alert database."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from nids.alert_store import AlertStore  # noqa: E402
from nids.version import PRODUCT, __version__  # noqa: E402

SEVERITY_NAMES = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _ts(value) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")


def _ascii_timeline(series) -> str:
    """Render the hourly alert buckets as a simple bar chart in text."""
    if not series:
        return "_no data_"
    buckets = [s for s in series if s["count"] > 0][-24:]
    if not buckets:
        return "_no alerts in the last hour of data_"
    peak = max(s["count"] for s in buckets) or 1
    lines = ["```", f"{'time':17s} {'count':>6s}  chart"]
    for s in buckets:
        bar = "#" * max(1, int(50 * s["count"] / peak))
        lines.append(f"{_ts(s['ts'])[11:]:17s} {s['count']:>6d}  {bar}")
    lines.append("```")
    return "\n".join(lines)


def generate_report(config: dict, out_dir: str | Path | None = None) -> list:
    store = AlertStore(config["general"]["db_path"])
    stats = store.stats()
    out_dir = Path(out_dir) if out_dir else (PROJECT_ROOT / "report")
    out_dir.mkdir(parents=True, exist_ok=True)

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    csv_path = out_dir / "incident_report.csv"
    n_exported = store.export_csv(csv_path)

    severity = stats["by_severity"]
    total = stats["total_alerts"]

    md = []
    md.append(f"# Network Intrusion Detection - Incident Report")
    md.append("")
    md.append(f"**Generated:** {generated}  ")
    md.append(f"**Tool:** {PRODUCT} v{__version__}  ")
    md.append(f"**Data source:** `{config['general']['db_path']}`")
    md.append("")
    md.append("## 1. Executive summary")
    md.append("")
    md.append(f"* **{total:,}** alerts were recorded in total.")
    md.append(f"* **{severity.get(4, 0):,}** critical and **{severity.get(3, 0):,}** high "
              "severity detections require review.")
    md.append(f"* **{stats['unique_sources']}** unique source addresses triggered alerts.")
    md.append(f"* **{stats['active_blocks']}** source IPs are currently blocked by the "
              "response engine.")
    if stats["first_alert_ts"]:
        md.append(f"* Detection window: {_ts(stats['first_alert_ts'])} to "
                  f"{_ts(stats['last_alert_ts'])}.")
    md.append("")

    md.append("## 2. Severity distribution")
    md.append("")
    md.append("| Severity | Count | Share |")
    md.append("|----------|------:|------:|")
    for level in (4, 3, 2, 1):
        count = severity.get(level, 0)
        share = f"{100.0 * count / total:.1f}%" if total else "0%"
        md.append(f"| {level} - {SEVERITY_NAMES[level]} | {count:,} | {share} |")
    md.append("")

    md.append("## 3. Attack categories")
    md.append("")
    md.append("| Category | Alerts |")
    md.append("|----------|-------:|")
    for row in stats["by_category"]:
        md.append(f"| {row['category']} | {row['count']:,} |")
    md.append("")

    md.append("## 4. Top attacking sources")
    md.append("")
    md.append("| Source IP | Alerts | Highest severity |")
    md.append("|-----------|-------:|-----------------:|")
    for row in stats["top_sources"]:
        md.append(f"| `{row['ip']}` | {row['count']:,} | "
                  f"{row['max_severity']} ({SEVERITY_NAMES.get(row['max_severity'], '?')}) |")
    md.append("")

    md.append("## 5. Alert timeline (per minute, last 24 active buckets)")
    md.append("")
    md.append(_ascii_timeline(store.timeseries(minutes=24 * 60, bucket_seconds=60)))
    md.append("")

    blocks = store.block_history()
    md.append("## 6. Response actions (blocks)")
    md.append("")
    if blocks:
        md.append("| IP | Mode | Created | Expires | Reason |")
        md.append("|----|------|---------|---------|--------|")
        for b in blocks[:25]:
            md.append(f"| `{b['ip']}` | {b['mode']} | {b['created']} | {b['expires']} "
                      f"| {b['reason']} |")
    else:
        md.append("_No blocking actions were executed._")
    md.append("")

    md.append("## 7. Detection coverage")
    md.append("")
    md.append("| Detector / engine | Alerts |")
    md.append("|-------------------|-------:|")
    for row in stats["by_detector"]:
        md.append(f"| {row['detector']} | {row['count']:,} |")
    md.append("")

    md.append("## 8. Recommended next steps")
    md.append("")
    md.append("1. Triage every critical alert and confirm whether the source IP is a "
              "known asset or scanner.")
    md.append("2. For confirmed incidents, ensure the block entries were promoted to "
              "firewall rules (`response.mode: active`).")
    md.append("3. Review `rules/custom.rules` tuning: thresholds that fire constantly "
              "should be raised, silent rules investigated.")
    md.append("4. Archive this report alongside the exported CSV for the audit trail.")
    md.append("")

    md_path = out_dir / "incident_report.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return [str(md_path), str(csv_path)]


if __name__ == "__main__":
    from nids.config import load_config
    cfg = load_config(PROJECT_ROOT / "config" / "nids_config.yaml", base_dir=PROJECT_ROOT)
    for p in generate_report(cfg):
        print("Report written:", p)
