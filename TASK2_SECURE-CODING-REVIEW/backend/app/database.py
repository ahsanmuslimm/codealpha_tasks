import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import get_settings

settings = get_settings()

def _create_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    try:
        return create_engine(url)
    except ModuleNotFoundError as exc:
        if "psycopg2" in str(exc):
            fallback = "sqlite:///./codesentry.db"
            print(f"WARNING: psycopg2 unavailable, falling back to {fallback}")
            return create_engine(fallback, connect_args={"check_same_thread": False})
        raise

engine = _create_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
