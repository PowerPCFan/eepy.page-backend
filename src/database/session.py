import logging
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sqlmodel import Session, SQLModel, create_engine

import models.tables  # noqa: F401
from config.env import Environment

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

_default_engine: "Engine | None" = None


def normalize_postgres_url(url: str | None = None) -> str:
    raw = (url or Environment.postgres_url() or "").strip()
    if not raw:
        msg = "POSTGRES_URL environment variable must be set"
        raise RuntimeError(msg)
    if raw.startswith("postgres://"):
        return "postgresql+psycopg://" + raw.removeprefix("postgres://")
    if raw.startswith("postgresql://"):
        return "postgresql+psycopg://" + raw.removeprefix("postgresql://")
    if not raw.startswith("postgresql+"):
        msg = f"Unsupported database URL scheme (PostgreSQL required): {raw.split('://', 1)[0]}"
        raise ValueError(msg)
    return raw


def create_db_engine(
    url: str | None = None,
    *,
    init_tables: bool = True,
) -> "Engine":
    normalized_url = normalize_postgres_url(url)
    engine = create_engine(
        normalized_url,
        pool_pre_ping=True,
        pool_recycle=1800,
    )

    if init_tables:
        init_db(engine)

    return engine


def init_db(engine: "Engine") -> None:
    try:
        SQLModel.metadata.create_all(engine)
    except Exception:
        logger.exception("Failed to initialize database schema")


def get_engine() -> "Engine":
    global _default_engine  # noqa: PLW0603
    if _default_engine is None:
        _default_engine = create_db_engine()
    return _default_engine


def set_engine(engine: "Engine") -> None:
    global _default_engine  # noqa: PLW0603
    _default_engine = engine


@contextmanager
def session_scope(engine: "Engine | None" = None) -> Iterator[Session]:
    target_engine = engine or get_engine()
    with Session(target_engine, expire_on_commit=False) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def get_session() -> Generator[Session]:
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
