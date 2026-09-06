from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "CodeSentry"
    debug: bool = False

    database_url: str = "postgresql://codesentry:codesentry@db:5432/codesentry"
    redis_url: str = "redis://redis:6379/0"

    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24

    max_upload_size_bytes: int = 200 * 1024 * 1024  # 200 MB
    max_zip_entries: int = 10_000
    max_extracted_size_bytes: int = 500 * 1024 * 1024  # 500 MB

    scan_timeout_seconds: int = 600  # 10 minutes
    scan_memory_limit: str = "2g"
    scan_cpu_limit: float = 2.0

    uploads_dir: str = "/app/uploads"
    artifacts_dir: str = "/app/artifacts"


@lru_cache
def get_settings() -> Settings:
    return Settings()
