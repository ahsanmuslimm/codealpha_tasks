#!/usr/bin/env python3
"""
Rebuilds the fixture Semgrep JSON outputs with real code snippets.
Semgrep's OSS mode obfuscates `lines` with "requires login" when run
without an account token. This script patches them with the actual source
lines so the normalizer stores meaningful evidence in the DB.

Run from the repo root:
    python fixtures/outputs/rebuild_fixtures.py
"""
import json
import os
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent.parent  # fixtures/
OUTPUTS_DIR = Path(__file__).parent          # fixtures/outputs/


def _read_lines(rel_path: str) -> list[str]:
    """Return source file lines (1-indexed: lines[0] is line 1)."""
    abs_path = (FIXTURES_DIR / rel_path).resolve()
    # Fall back to using the path as-is if the relative resolution doesn't work.
    if not abs_path.exists():
        abs_path = Path(rel_path)
    if abs_path.exists():
        return [""] + abs_path.read_text(encoding="utf-8").splitlines()
    return []


def _extract_snippet(source_lines: list[str], line_start: int, line_end: int) -> str:
    if not source_lines or line_start is None:
        return ""
    end = min(line_end or line_start, len(source_lines) - 1)
    return "\n".join(source_lines[line_start : end + 1]).strip()


def patch_output(json_file: Path) -> None:
    data = json.loads(json_file.read_text(encoding="utf-8"))
    patched = 0
    for result in data.get("results", []):
        original_path = result.get("path", "")
        # Try to find the file relative to fixtures dir
        rel = None
        for fixture_subdir in FIXTURES_DIR.iterdir():
            if not fixture_subdir.is_dir():
                continue
            # Match by filename suffix
            for f in fixture_subdir.rglob("*"):
                if f.is_file() and original_path.replace("\\", "/").endswith(
                    str(f.relative_to(FIXTURES_DIR)).replace("\\", "/")
                ):
                    rel = f
                    break
            if rel:
                break

        if rel and rel.exists():
            source_lines = [""] + rel.read_text(encoding="utf-8").splitlines()
            line_start = result.get("start", {}).get("line")
            line_end = result.get("end", {}).get("line")
            snippet = _extract_snippet(source_lines, line_start, line_end)
            if snippet:
                result["extra"]["lines"] = snippet
                patched += 1

    json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Patched {patched} snippets in {json_file.name}")


if __name__ == "__main__":
    for fname in ["sample-python.json", "sample-js.json", "sample-java.json"]:
        patch_output(OUTPUTS_DIR / fname)
    print("Done.")
