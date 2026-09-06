"""
Standalone adversarial tests for CodeSentry input validators.
Run with: python tests/test_validation.py
"""
import os
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.services.validation import validate_git_url, safe_extract_zip, ValidationError


def test_git_url_blocks_private_ips():
    blocked = [
        "http://127.0.0.1/repo.git",
        "https://10.0.0.1/repo.git",
        "https://192.168.1.1/repo.git",
        "https://169.254.169.254/repo.git",
        "https://0.0.0.0/repo.git",
    ]
    for url in blocked:
        try:
            validate_git_url(url)
            raise AssertionError(f"Should have blocked {url}")
        except ValidationError:
            pass
    print("PASS: private/link-local IPs blocked")


def test_git_url_blocks_bad_schemes():
    try:
        validate_git_url("ftp://example.com/repo.git")
        raise AssertionError("Should have blocked ftp scheme")
    except ValidationError:
        pass
    print("PASS: bad schemes blocked")


def test_git_url_allows_public_https():
    assert validate_git_url("https://github.com/owasp/juice-shop.git")
    print("PASS: public HTTPS allowed")


def test_zip_path_traversal_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "traversal.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../evil.txt", "payload")
        try:
            safe_extract_zip(zip_path, os.path.join(tmp, "out"), 100, 1024 * 1024)
            raise AssertionError("Path traversal should be rejected")
        except ValidationError:
            pass
    print("PASS: path traversal rejected")


def test_zip_too_many_entries_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "many.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(5):
                zf.writestr(f"f{i}.txt", "x")
        try:
            safe_extract_zip(zip_path, os.path.join(tmp, "out"), 2, 1024 * 1024)
            raise AssertionError("Too many entries should be rejected")
        except ValidationError as exc:
            assert "too many entries" in str(exc).lower()
    print("PASS: max entries enforced")


def test_zip_oversized_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "big.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("big.txt", "x" * 100)
        try:
            safe_extract_zip(zip_path, os.path.join(tmp, "out"), 100, 50)
            raise AssertionError("Oversized extraction should be rejected")
        except ValidationError as exc:
            assert "would extract" in str(exc).lower()
    print("PASS: max extracted size enforced")


def test_zip_safe_extract_works():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "safe.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("src/main.py", "print('hello')")
            zf.writestr("README.md", "# ok")
        out = safe_extract_zip(zip_path, os.path.join(tmp, "out"), 100, 1024 * 1024)
        assert os.path.exists(os.path.join(out, "src", "main.py"))
        assert os.path.exists(os.path.join(out, "README.md"))
    print("PASS: safe extraction works")


if __name__ == "__main__":
    test_git_url_blocks_private_ips()
    test_git_url_blocks_bad_schemes()
    test_git_url_allows_public_https()
    test_zip_path_traversal_rejected()
    test_zip_too_many_entries_rejected()
    test_zip_oversized_rejected()
    test_zip_safe_extract_works()
    print("\nAll validation tests passed.")
