import os
import shutil
import uuid
from pathlib import Path
from typing import Optional

from fastapi import UploadFile

from app.config import Settings


def ensure_dir(path: str) -> str:
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def save_upload(
    upload: UploadFile,
    uploads_dir: str,
    max_size_bytes: int,
) -> str:
    """Stream-save an uploaded file to disk with size enforcement."""
    ensure_dir(uploads_dir)
    ext = Path(str(upload.filename)).suffix.lower()
    if ext not in {".zip"}:
        raise ValueError("Only .zip uploads are supported")

    dest_name = f"{uuid.uuid4()}{ext}"
    dest_path = os.path.join(uploads_dir, dest_name)

    written = 0
    with open(dest_path, "wb") as f:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > max_size_bytes:
                f.close()
                os.remove(dest_path)
                raise ValueError(
                    f"Upload exceeds maximum size of {max_size_bytes} bytes"
                )
            f.write(chunk)

    return dest_path


def make_project_dir(base_dir: str, project_id: str) -> str:
    path = os.path.join(base_dir, str(project_id))
    return ensure_dir(path)


def cleanup_path(path: Optional[str]) -> None:
    if path and os.path.exists(path):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.remove(path)
            except OSError:
                pass
