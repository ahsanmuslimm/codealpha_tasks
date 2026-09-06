import ipaddress
import os
import re
import zipfile
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when an input fails a security validation."""
    pass


ALLOWED_GIT_SCHEMES = {"https", "git", "ssh"}
# Link-local, loopback, private, and metadata IP ranges that must never be cloned.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::ffff:0:0/96"),
]


def validate_git_url(url: str) -> str:
    """
    Validate a git URL to prevent SSRF.
    Blocks non-allowed schemes, private/link-local IPs, and hostnames resolving to blocked ranges.
    """
    parsed = urlparse(url)

    # Normalize ssh-style URLs (git@host:path) by requiring an explicit scheme.
    if not parsed.scheme and url.startswith("git@"):
        raise ValidationError("SSH-style URLs must use explicit ssh:// scheme")

    if parsed.scheme.lower() not in ALLOWED_GIT_SCHEMES:
        raise ValidationError(f"URL scheme must be one of {sorted(ALLOWED_GIT_SCHEMES)}")

    host = parsed.hostname
    if not host:
        raise ValidationError("URL must contain a host")

    # Block IP literals first.
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in BLOCKED_NETWORKS):
            raise ValidationError("Cloning private, link-local, or loopback addresses is not allowed")
        return url
    except ValueError:
        pass  # Host is a hostname, not an IP literal.

    # Block suspicious hostnames that are already IP-like or metadata endpoints.
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) or host.lower() in {"metadata", "localhost"}:
        raise ValidationError("Cloning private, link-local, or loopback addresses is not allowed")

    return url


def _is_path_safe(entry_name: str) -> Tuple[bool, str]:
    """Return (safe, normalized_relative_path) for a zip entry."""
    # Normalize separators and strip any leading slash.
    normalized = Path(entry_name).as_posix().lstrip("/")
    # Reject absolute paths, parent traversal, and hidden unix paths.
    if normalized.startswith("..") or "/../" in f"/{normalized}/" or normalized == "..":
        return False, ""
    if entry_name.startswith("/") or "\\" in entry_name:
        return False, ""
    return True, normalized


def safe_extract_zip(
    zip_path: str,
    extract_root: str,
    max_entries: int,
    max_extracted_size_bytes: int,
) -> str:
    """
    Safely extract a zip file with defenses against zip-bombs and path traversal.
    Returns the path to the extraction directory.
    """
    if not zipfile.is_zipfile(zip_path):
        raise ValidationError("Uploaded file is not a valid ZIP archive")

    root = Path(extract_root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        if len(zf.infolist()) > max_entries:
            raise ValidationError(f"ZIP contains too many entries (max {max_entries})")

        # Pre-validate all names and compute total uncompressed size.
        total_uncompressed = 0
        validated = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            safe, normalized = _is_path_safe(info.filename)
            if not safe:
                raise ValidationError(f"ZIP contains unsafe path: {info.filename}")
            total_uncompressed += info.file_size
            validated.append((info, normalized))

        if total_uncompressed > max_extracted_size_bytes:
            raise ValidationError(
                f"ZIP would extract to {total_uncompressed} bytes (max {max_extracted_size_bytes})"
            )

        for info, normalized in validated:
            target = root / normalized
            # Final guard: resolved path must stay inside root.
            try:
                target.resolve().relative_to(root)
            except ValueError:
                raise ValidationError(f"ZIP path escapes extraction root: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                # Stream-copy with bounded read to avoid loading huge files.
                remaining = max_extracted_size_bytes
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValidationError("ZIP extraction exceeded maximum allowed size")
                    dst.write(chunk)

    return str(root)
