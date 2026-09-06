#!/usr/bin/env python3
"""
CodeSentry scan worker.

Environment variables:
- SCAN_ID: UUID of the scan job.
- PROJECT_SOURCE_TYPE: "git" or "upload".
- PROJECT_SOURCE_REF: git URL or path to extracted upload on host (mounted to /workspace/source).

Outputs (in /workspace/out):
- semgrep.json: raw Semgrep JSON output.
- osv.json: raw OSV-Scanner JSON output.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SOURCE_DIR = Path("/workspace/source")
OUT_DIR = Path("/workspace/out")

SEMGRP_RULES = [
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/secrets",
]


def log(msg: str) -> None:
    print(f"[codesentry-worker] {msg}", flush=True)


def prepare_source() -> None:
    source_type = os.environ.get("PROJECT_SOURCE_TYPE", "upload")
    source_ref = os.environ.get("PROJECT_SOURCE_REF", "")

    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    if source_type == "git":
        if not source_ref:
            raise ValueError("PROJECT_SOURCE_REF is required for git projects")
        # Clone with a bounded timeout. Network is expected to be enabled for this step.
        log(f"Cloning {source_ref}")
        subprocess.run(
            ["git", "clone", "--depth", "1", source_ref, str(SOURCE_DIR)],
            check=True,
            timeout=300,
            capture_output=True,
            text=True,
        )
    else:
        # Upload source is already mounted read-only at /workspace/source.
        if not any(SOURCE_DIR.iterdir()):
            raise ValueError("Source directory is empty; upload not mounted correctly")
        log("Using mounted upload source")


def run_semgrep() -> Path:
    output = OUT_DIR / "semgrep.json"
    cmd = [
        "semgrep",
        "--config", ",".join(SEMGRP_RULES),
        "--json",
        "--output", str(output),
        "--metrics", "off",
        "--no-suppress-errors",
        str(SOURCE_DIR),
    ]
    log("Running Semgrep")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=540)
    # Semgrep may return non-zero when findings exist; we still want the JSON.
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Semgrep failed: {result.stderr}")
    return output


def run_osv() -> Path:
    output = OUT_DIR / "osv.json"
    cmd = [
        "osv-scanner",
        "--format", "json",
        "--output", str(output),
        "--recursive",
        str(SOURCE_DIR),
    ]
    log("Running OSV-Scanner")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    # OSV returns 1 when vulnerabilities are found.
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"OSV-Scanner failed: {result.stderr}")
    return output


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = os.environ.get("SCAN_ID", "unknown")
    log(f"Starting scan {scan_id}")

    try:
        prepare_source()
        run_semgrep()
        run_osv()
        log("Scan complete")
        return 0
    except Exception as exc:
        log(f"Scan failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
