#!/usr/bin/env python3
"""Import Suricata EVE JSON alerts into the PyNIDS alert database.

This is the bridge that lets a *real* Suricata deployment use the bundled
dashboard and response tooling:

    python run_nids.py --import-eve /var/log/suricata/eve.json     # one-shot
    python run_nids.py --service --eve /var/log/suricata/eve.json  # tail -f
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from nids.alert import Alert  # noqa: E402
from nids.alert_store import AlertStore  # noqa: E402

logger = logging.getLogger("nids.eve")


def _parse_eve_timestamp(value: str) -> float:
    """Suricata EVE timestamp -> unix epoch (handles '+0000' style offsets)."""
    try:
        import re
        clean = value.replace("+0000", "Z")
        base = time.mktime(time.strptime(clean.split(".")[0], "%Y-%m-%dT%H:%M:%S"))
        frac = 0.0
        if "." in value:
            frac_part = value.split(".")[1]
            frac_digits = re.match(r"\d+", frac_part)
            if frac_digits:
                frac = float("0." + frac_digits.group())
        return base + frac
    except (ValueError, IndexError):
        try:
            from datetime import datetime, timezone
            return datetime.fromisoformat(value.replace("+0000", "+00:00")
                                          .replace("Z", "+00:00")).timestamp()
        except ValueError:
            return time.time()


def eve_line_to_alert(record: dict) -> Optional[Alert]:
    """Convert one EVE JSON record (event_type=alert) to an Alert."""
    if record.get("event_type") != "alert":
        return None
    alert_info = record.get("alert", {})
    suricata_severity = int(alert_info.get("severity", 3))
    # Suricata: 1 = highest priority.  Ours: 4 = critical.
    our_severity = max(1, min(4, 5 - suricata_severity))
    return Alert(
        timestamp=_parse_eve_timestamp(record.get("timestamp", "")),
        name=alert_info.get("signature", "Unknown Suricata signature"),
        category=alert_info.get("category") or "Signature",
        severity=our_severity,
        detector="suricata",
        protocol=str(record.get("proto", "IP")).upper(),
        src_ip=record.get("src_ip"),
        src_port=record.get("src_port"),
        dst_ip=record.get("dest_ip"),
        dst_port=record.get("dest_port"),
        sid=alert_info.get("signature_id"),
        details=f"suricata sid:{alert_info.get('signature_id')} "
                f"gid:{alert_info.get('gid', 1)}",
    )


def import_eve_file(config: dict, path: str, quiet: bool = False) -> int:
    """Import a whole eve.json file once. Returns the number of alerts added."""
    store = AlertStore(config["general"]["db_path"])
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("skipping malformed EVE line")
                continue
            alert = eve_line_to_alert(record)
            if alert:
                store.save_alert(alert)
                count += 1
    if not quiet:
        logger.info("Imported %d alerts from %s", count, path)
    return count


def tail_eve(config: dict, path: str, interval: float = 5.0,
             stop_event: Optional[threading.Event] = None) -> None:
    """Continuously follow an eve.json file (like tail -f) and ingest alerts."""
    store = AlertStore(config["general"]["db_path"])
    eve_path = Path(path)
    seen = 0
    while not (stop_event is not None and stop_event.is_set()):
        if not eve_path.exists():
            logger.warning("EVE file %s does not exist yet - waiting", path)
            time.sleep(interval)
            continue
        with eve_path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0) if seen == 0 else None
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                alert = eve_line_to_alert(record)
                if alert:
                    store.save_alert(alert)
                    store.heartbeat(f"eve:{alert.name[:40]}")
                    print(alert.describe(), flush=True)
                    seen += 1
        time.sleep(interval)


if __name__ == "__main__":
    from nids.config import load_config
    cfg = load_config(PROJECT_ROOT / "config" / "nids_config.yaml", base_dir=PROJECT_ROOT)
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/eve_sample.jsonl"
    print(f"Imported {import_eve_file(cfg, target)} alerts from {target}")
