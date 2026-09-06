#!/usr/bin/env python3
"""Flask dashboard (SOC console) for PyNIDS.

Reads the shared SQLite alert DB and exposes JSON APIs used by the
single-page UI in templates/index.html + static/.  The dashboard can run
while the detection engine is running in another process - they share the
database.  Manual block/unblock actions go through the ResponseEngine.

Run:  python run_nids.py --dashboard   (or python -m dashboard.app)
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, render_template, request

PROJECT_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger("nids.dashboard")


def create_app(config: dict):
    """Application factory."""
    from nids.alert_store import AlertStore
    from nids.response import ResponseEngine

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["nids_config"] = config
    store = AlertStore(config["general"]["db_path"])
    response_engine = ResponseEngine(config, store)
    app.config["nids_store"] = store
    app.config["nids_response"] = response_engine

    # ---------------- pages ----------------

    @app.route("/")
    def index():
        return render_template("index.html",
                               refresh_seconds=int(config["dashboard"].get("refresh_seconds", 5)))

    # ---------------- JSON APIs ----------------

    @app.route("/api/health")
    def health():
        return jsonify({"ok": True, "service": "pynids-dashboard"})

    @app.route("/api/alerts")
    def alerts():
        try:
            limit = min(int(request.args.get("limit", 100)), 1000)
        except ValueError:
            limit = 100
        severity = request.args.get("severity", type=int)
        category = request.args.get("category") or None
        src = request.args.get("src") or None
        search = request.args.get("q") or None
        rows = store.recent_alerts(limit=limit, severity=severity, category=category,
                                   src_ip=src, search=search)
        return jsonify({"count": len(rows), "alerts": [a.to_dict() for a in rows]})

    @app.route("/api/stats")
    def stats():
        data = store.stats()
        data["engine"] = store.engine_status()
        data["db_path"] = config["general"]["db_path"]
        return jsonify(data)

    @app.route("/api/timeseries")
    def timeseries():
        try:
            minutes = min(int(request.args.get("minutes", 60)), 24 * 60)
        except ValueError:
            minutes = 60
        return jsonify({"minutes": minutes,
                        "series": store.timeseries(minutes=minutes, bucket_seconds=60)})

    @app.route("/api/blocked")
    def blocked():
        store.expire_old_blocks()
        return jsonify({"count": len(store.active_blocks()),
                        "blocks": store.active_blocks(),
                        "history": store.block_history(limit=50)})

    @app.route("/api/block", methods=["POST"])
    def block_ip():
        payload = request.get_json(silent=True) or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"ok": False, "error": "ip is required"}), 400
        reason = (payload.get("reason") or "manual block from dashboard").strip()
        created, mode = response_engine.manual_block(ip, reason=reason)
        return jsonify({"ok": True, "created": created, "mode": mode,
                        "message": f"{ip} blocked (mode={mode})" if created
                        else f"{ip} was already blocked - window extended"})

    @app.route("/api/unblock", methods=["POST"])
    def unblock_ip():
        payload = request.get_json(silent=True) or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"ok": False, "error": "ip is required"}), 400
        lifted = response_engine.manual_unblock(ip)
        return jsonify({"ok": lifted,
                        "message": f"{ip} unblocked" if lifted
                        else f"{ip} had no active block"})

    @app.route("/api/export/csv")
    def export_csv():
        from datetime import datetime
        store.export_csv(PROJECT_ROOT / "data" / "alerts_export.csv")
        path = PROJECT_ROOT / "data" / "alerts_export.csv"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Response(
            path.read_text(encoding="utf-8"),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=pynids_alerts_{stamp}.csv"},
        )

    # error handler: JSON APIs never return HTML stack traces
    @app.errorhandler(Exception)
    def on_error(exc):
        logger.exception("dashboard error")
        return jsonify({"ok": False, "error": str(exc)}), 500

    return app


def run_dashboard(config: dict, host: Optional[str] = None, port: Optional[int] = None) -> None:
    app = create_app(config)
    host = host or config["dashboard"].get("host", "127.0.0.1")
    port = port or int(config["dashboard"].get("port", 5000))
    print(f"[*] Dashboard starting on http://{host}:{port}  (Ctrl-C to stop)")
    app.run(host=host, port=port, debug=False, use_reloader=False)


def start_dashboard_thread(config: dict, host: Optional[str] = None,
                           port: Optional[int] = None) -> threading.Thread:
    """Run the dashboard in a daemon thread (used by --service)."""
    app = create_app(config)
    host = host or config["dashboard"].get("host", "127.0.0.1")
    port = port or int(config["dashboard"].get("port", 5000))
    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        name="nids-dashboard", daemon=True)
    thread.start()
    print(f"[*] Dashboard running in background on http://{host}:{port}")
    return thread


if __name__ == "__main__":
    from nids.config import load_config
    cfg = load_config(PROJECT_ROOT / "config" / "nids_config.yaml", base_dir=PROJECT_ROOT)
    run_dashboard(cfg)
