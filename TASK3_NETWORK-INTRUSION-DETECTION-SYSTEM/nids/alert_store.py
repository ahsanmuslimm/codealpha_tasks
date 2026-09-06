"""SQLite persistence for alerts, IP blocks and engine metadata.

The store is intentionally process-safe: the detection engine writes while the
Flask dashboard reads (and the dashboard can also write manual blocks), so all
access goes through an RLock and the database runs in WAL mode.
"""

from __future__ import annotations

import csv
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from nids.alert import Alert

logger = logging.getLogger("nids.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    ts_iso     TEXT,
    sid        INTEGER,
    name       TEXT,
    category   TEXT,
    severity   INTEGER,
    protocol   TEXT,
    src_ip     TEXT,
    src_port   INTEGER,
    dst_ip     TEXT,
    dst_port   INTEGER,
    details    TEXT,
    detector   TEXT,
    action     TEXT DEFAULT 'logged'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts (ts);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts (category);
CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts (src_ip);

CREATE TABLE IF NOT EXISTS blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    reason      TEXT,
    mode        TEXT,                 -- 'simulate' | 'active' | 'manual'
    created_ts  REAL NOT NULL,
    expires_ts  REAL,
    active      INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks (ip);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class AlertStore:
    """Thread-safe SQLite-backed store shared by the engine and dashboard."""

    def __init__(self, db_path: str | Path = "data/alerts.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def save_alert(self, alert: Alert) -> Alert:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO alerts (ts, ts_iso, sid, name, category, severity, protocol,
                                        src_ip, src_port, dst_ip, dst_port, details, detector, action)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                alert.row(),
            )
            self._conn.commit()
            alert.alert_id = cur.lastrowid
        return alert

    def recent_alerts(
        self,
        limit: int = 100,
        severity: Optional[int] = None,
        category: Optional[str] = None,
        src_ip: Optional[str] = None,
        search: Optional[str] = None,
        since_ts: Optional[float] = None,
    ) -> List[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []
        if severity:
            query += " AND severity >= ?"
            params.append(int(severity))
        if category:
            query += " AND category = ?"
            params.append(category)
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        if since_ts:
            query += " AND ts >= ?"
            params.append(float(since_ts))
        if search:
            query += " AND (name LIKE ? OR details LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like, like])
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [Alert.from_row(tuple(r)) for r in rows]

    def count_alerts(self, severity: Optional[int] = None) -> int:
        query = "SELECT COUNT(*) FROM alerts"
        params: List[Any] = []
        if severity:
            query += " WHERE severity >= ?"
            params.append(int(severity))
        with self._lock:
            return int(self._conn.execute(query, params).fetchone()[0])

    # -- aggregates --------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = int(self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            by_severity = {
                int(r["severity"]): int(r["c"])
                for r in self._conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity")
            }
            by_category = [
                {"category": r["category"] or "Unknown", "count": int(r["c"])}
                for r in self._conn.execute(
                    "SELECT category, COUNT(*) AS c FROM alerts GROUP BY category ORDER BY c DESC")
            ]
            by_detector = [
                {"detector": r["detector"] or "unknown", "count": int(r["c"])}
                for r in self._conn.execute(
                    "SELECT detector, COUNT(*) AS c FROM alerts GROUP BY detector ORDER BY c DESC")
            ]
            top_sources = [
                {"ip": r["src_ip"], "count": int(r["c"]),
                 "max_severity": int(r["ms"])}
                for r in self._conn.execute(
                    """SELECT src_ip, COUNT(*) AS c, MAX(severity) AS ms FROM alerts
                       WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY c DESC LIMIT 10""")
            ]
            first, last = self._conn.execute(
                "SELECT MIN(ts), MAX(ts) FROM alerts").fetchone()
            unique_sources = int(self._conn.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE src_ip IS NOT NULL").fetchone()[0])
        return {
            "total_alerts": total,
            "unique_sources": unique_sources,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_detector": by_detector,
            "top_sources": top_sources,
            "first_alert_ts": first,
            "last_alert_ts": last,
            "active_blocks": len(self.active_blocks()),
        }

    def timeseries(self, minutes: int = 60, bucket_seconds: int = 60) -> List[Dict[str, Any]]:
        """Alert counts bucketed over the trailing *minutes* window."""
        end = time.time()
        start = end - minutes * 60
        with self._lock:
            rows = self._conn.execute(
                """SELECT CAST(ts / ? AS INT) * ? AS bucket, COUNT(*) AS c, MAX(severity) AS max_sev
                   FROM alerts WHERE ts >= ? GROUP BY bucket ORDER BY bucket""",
                (bucket_seconds, bucket_seconds, start),
            ).fetchall()
        by_bucket = {int(r["bucket"]): {"count": int(r["c"]), "max_sev": int(r["max_sev"] or 0)}
                     for r in rows}
        series = []
        bucket = int(start // bucket_seconds) * bucket_seconds
        while bucket <= end:
            entry = by_bucket.get(bucket, {"count": 0, "max_sev": 0})
            series.append({"ts": bucket, "count": entry["count"], "max_severity": entry["max_sev"]})
            bucket += bucket_seconds
        return series

    def top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT dst_port AS port, COUNT(*) AS c FROM alerts
                   WHERE dst_port IS NOT NULL GROUP BY dst_port ORDER BY c DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [{"port": int(r["port"]), "count": int(r["c"])} for r in rows]

    # ------------------------------------------------------------------
    # Blocks (response state)
    # ------------------------------------------------------------------

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM blocks WHERE ip = ? AND active = 1 ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
        return row is not None

    def save_block(self, ip: str, reason: str, mode: str = "simulate",
                   ttl_seconds: Optional[int] = None) -> bool:
        """Record a block. Returns False when the IP is already actively blocked."""
        now = time.time()
        expires = now + ttl_seconds if ttl_seconds else None
        with self._lock:
            existing = self._conn.execute(
                "SELECT id, expires_ts FROM blocks WHERE ip = ? AND active = 1", (ip,)
            ).fetchone()
            if existing:
                # extend the window instead of stacking duplicate rows
                new_exp = max(existing["expires_ts"] or 0, expires or 0) or None
                self._conn.execute(
                    "UPDATE blocks SET expires_ts = ?, reason = ? WHERE id = ?",
                    (new_exp, reason, existing["id"]),
                )
                self._conn.commit()
                return False
            self._conn.execute(
                """INSERT INTO blocks (ip, reason, mode, created_ts, expires_ts, active)
                   VALUES (?,?,?,?,?,1)""",
                (ip, reason, mode, now, expires),
            )
            self._conn.commit()
        return True

    def lift_block(self, ip: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE blocks SET active = 0 WHERE ip = ? AND active = 1", (ip,))
            self._conn.commit()
        return cur.rowcount > 0

    def expire_old_blocks(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE blocks SET active = 0 WHERE active = 1 AND expires_ts IS NOT NULL "
                "AND expires_ts < ?", (time.time(),))
            self._conn.commit()
        if cur.rowcount:
            logger.info("Expired %s auto-unblocked IP(s)", cur.rowcount)
        return cur.rowcount

    def active_blocks(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM blocks WHERE active = 1 ORDER BY created_ts DESC""").fetchall()
        return [self._block_dict(r) for r in rows]

    def block_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM blocks ORDER BY created_ts DESC LIMIT ?", (limit,)).fetchall()
        return [self._block_dict(r) for r in rows]

    @staticmethod
    def _block_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"], "ip": row["ip"], "reason": row["reason"], "mode": row["mode"],
            "created_ts": row["created_ts"],
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["created_ts"])),
            "expires_ts": row["expires_ts"],
            "expires": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["expires_ts"]))
                       if row["expires_ts"] else "never (permanent)",
        }

    # ------------------------------------------------------------------
    # Engine metadata (heartbeat etc.)
    # ------------------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
            self._conn.commit()

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def heartbeat(self, engine_info: str = "") -> None:
        self.set_meta("engine_heartbeat", f"{time.time():.3f}|{engine_info}")

    def engine_status(self, stale_after: float = 15.0) -> Dict[str, Any]:
        raw = self.get_meta("engine_heartbeat")
        if not raw:
            return {"running": False, "info": "no engine has run against this database yet"}
        try:
            ts_str, info = raw.split("|", 1)
            age = time.time() - float(ts_str)
        except ValueError:  # pragma: no cover - defensive
            return {"running": False, "info": "unreadable heartbeat"}
        return {"running": age < stale_after, "age": age, "info": info}

    # ------------------------------------------------------------------
    # Export / maintenance
    # ------------------------------------------------------------------

    def export_csv(self, path: str | Path, limit: Optional[int] = None) -> int:
        rows = self.recent_alerts(limit=limit or 1_000_000)
        rows = list(reversed(rows))  # chronological order
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = ["id", "timestamp", "time", "severity", "severity_name", "category",
                      "name", "detector", "protocol", "src_ip", "src_port", "dst_ip",
                      "dst_port", "sid", "action", "details"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for alert in rows:
                writer.writerow({k: alert.to_dict().get(k, "") for k in fieldnames})
        return len(rows)

    def purge_alerts(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alerts")
            self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
