"""Debug: trace what paths the task is using for the fixture scan."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.config import Settings
import app.config as _config_mod

TEST_SETTINGS = Settings(
    database_url="sqlite:///./codesentry_debug.db",
    redis_url="redis://localhost:6379/0",
    secret_key="debug-secret",
    use_docker_worker=False,
    celery_task_always_eager=True,
    uploads_dir="./uploads_test",
    artifacts_dir="./artifacts_test",
)
_config_mod.get_settings = lambda: TEST_SETTINGS

from app.tasks import _identify_fixture_by_content, _copy_fixture_output
from pathlib import Path

uploads_dir = Path("./uploads_test").resolve()
print(f"uploads_dir = {uploads_dir}")
print(f"exists = {uploads_dir.exists()}")
if uploads_dir.exists():
    for d in uploads_dir.iterdir():
        print(f"  subdir: {d.name}")
        if d.is_dir():
            files = list(d.rglob("*"))
            file_names = {f.name for f in files if f.is_file()}
            print(f"    files: {file_names}")
            fixture = _identify_fixture_by_content(d)
            print(f"    identified as: {fixture!r}")
