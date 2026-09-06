"""YAML configuration loading with sane defaults and deep merging."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("nids.config")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "home_net": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
        "whitelist_ips": ["127.0.0.1"],
        "db_path": "data/alerts.db",
        "alerts_jsonl": "data/alerts.jsonl",
        "log_level": "INFO",
    },
    "rules": {
        "file": "rules/custom.rules",
        "enabled": True,
    },
    "detectors": {
        "port_scan": {
            "enabled": True,
            "window_seconds": 30,
            "distinct_ports": 12,
            "cooldown_seconds": 45,
        },
        "brute_force": {
            "enabled": True,
            "window_seconds": 60,
            "attempt_threshold": 8,
            "cooldown_seconds": 60,
            "auth_ports": [21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900],
            "http_failure_codes": [401, 403],
            "http_failure_threshold": 10,
        },
        "dos": {
            "enabled": True,
            "syn_flood": {"window_seconds": 10, "packet_threshold": 100},
            "udp_flood": {"window_seconds": 10, "packet_threshold": 200},
            "icmp_flood": {"window_seconds": 10, "packet_threshold": 60},
            "http_flood": {"window_seconds": 10, "packet_threshold": 120},
            "cooldown_seconds": 60,
        },
        "arp_spoof": {
            "enabled": True,
            "gateways": [],
            "cooldown_seconds": 60,
        },
        "dns_tunnel": {
            "enabled": True,
            "max_label_length": 45,
            "max_name_length": 120,
            "entropy_threshold": 3.5,
            "min_entropy_label_length": 20,
            "query_rate_window": 60,
            "query_rate_threshold": 40,
            "cooldown_seconds": 60,
        },
        "web_attack": {
            "enabled": True,
            "cooldown_seconds": 10,
        },
    },
    "response": {
        "enabled": True,
        "mode": "simulate",                    # simulate | active
        "block_ttl_minutes": 30,
        "immediate_severity": 4,               # block instantly at/above this severity
        "escalate_min_severity": 3,            # escalate when alerts at/above this severity...
        "escalate_count": 4,                   # ...occur this many times...
        "escalate_window_minutes": 5,          # ...inside this window
        "whitelist_governs_active_only": True,  # simulate-mode records bypass the whitelist
        "notifications": {
            "webhook_url": "",
            "email": {
                "enabled": False,
                "smtp_host": "localhost",
                "smtp_port": 25,
                "from_addr": "nids@localhost",
                "to_addrs": [],
            },
        },
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5000,
        "refresh_seconds": 5,
    },
    "capture": {
        "bpf_filter": "",
        "promisc": True,
        "replay_speed": 10.0,                  # multiplier used by --replay-live
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base* (returns a new dict)."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _resolve_paths(config: Dict[str, Any], base_dir: Path) -> Dict[str, Any]:
    """Make relative file paths absolute against *base_dir*."""
    for key in ("db_path", "alerts_jsonl"):
        value = config["general"].get(key)
        if value and not Path(value).is_absolute():
            config["general"][key] = str((base_dir / value).resolve())
    rule_file = config["rules"].get("file")
    if rule_file and not Path(rule_file).is_absolute():
        config["rules"]["file"] = str((base_dir / rule_file).resolve())
    return config


def load_config(path: Optional[str | Path] = None, overrides: Optional[Dict[str, Any]] = None,
                base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load YAML config and deep-merge it over :data:`DEFAULT_CONFIG`.

    ``overrides`` (e.g. from CLI flags) always win.  Relative paths inside the
    config are resolved against *base_dir* (default: project root, or the YAML
    file's parent's parent when a file is given).
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        path = Path(path)
        if path.exists():
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - pyyaml is a hard dep
                raise RuntimeError("PyYAML is required to read config files") from exc
            with path.open("r", encoding="utf-8") as fh:
                user_cfg = yaml.safe_load(fh) or {}
            if not isinstance(user_cfg, dict):
                raise ValueError(f"Config root must be a mapping, got {type(user_cfg).__name__}")
            config = _deep_merge(config, user_cfg)
        else:
            logger.warning("Config file %s not found - using defaults", path)
    if overrides:
        config = _deep_merge(config, overrides)
    root = base_dir or (path.parent.parent if path and Path(path).exists() else PROJECT_ROOT)
    return _resolve_paths(config, Path(root))
