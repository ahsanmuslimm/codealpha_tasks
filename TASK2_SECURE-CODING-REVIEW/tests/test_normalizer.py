"""
Standalone test for the Semgrep normalizer.
Run with: python tests/test_normalizer.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.services.normalizer import normalize_semgrep


def main():
    outputs_dir = os.path.join(
        os.path.dirname(__file__), "..", "fixtures", "outputs"
    )
    for name in ["sample-python", "sample-js", "sample-java"]:
        path = os.path.join(outputs_dir, f"{name}.json")
        findings = normalize_semgrep(path)
        print(f"\n{name}: {len(findings)} normalized findings")
        for f in findings:
            print(
                f"  - {f.severity.value:8} {f.cwe_id or 'N/A':12} "
                f"{f.owasp_category or 'N/A':40} {f.file_path}:{f.line_start or '-'}"
            )


if __name__ == "__main__":
    main()
