"""Debug: run the task function directly to see what it does."""
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

# Now import tasks — at this point tasks.py calls get_settings() at module level
# to init celery_app. But since we replaced get_settings BEFORE the import, it
# should use our settings.
from app.tasks import run_scan, _copy_fixture_output, _identify_fixture_by_content, _run_direct_scan
from app.config import get_settings as gs
cfg = gs()
print(f"use_docker_worker = {cfg.use_docker_worker}")
print(f"celery_task_always_eager = {cfg.celery_task_always_eager}")
print(f"artifacts_dir = {cfg.artifacts_dir}")
print(f"uploads_dir = {cfg.uploads_dir}")

# Find an existing extracted project dir
from pathlib import Path
uploads = Path("./uploads_test")
source_dir = None
for d in uploads.iterdir():
    if d.is_dir() and "app.py" in {f.name for f in d.rglob("*")}:
        source_dir = str(d)
        break

if source_dir:
    print(f"\nTesting _run_direct_scan with source_dir={source_dir}")
    import tempfile, os
    with tempfile.TemporaryDirectory() as work_dir:
        sem, osv = _run_direct_scan(work_dir, source_dir, "test-scan-id")
        print(f"semgrep output: {sem}")
        print(f"  exists: {Path(sem).exists()}, size: {Path(sem).stat().st_size if Path(sem).exists() else 'N/A'}")
        if Path(sem).exists():
            import json
            data = json.loads(Path(sem).read_text())
            print(f"  results count: {len(data.get('results', []))}")
else:
    print("No source dir found")
