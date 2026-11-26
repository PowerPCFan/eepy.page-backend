from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from database.models.base import Base
from database.session import get_engine, rowcount, session_scope

if TYPE_CHECKING:
    from collections.abc import Generator

    from sqlalchemy.engine import Engine
    from sqlalchemy.orm import Session

logger: logging.Logger = logging.getLogger("eepy.page")


class Table[T: Base]:
    def __init__(self, db_engine: Engine | None, model_cls: type[T]) -> None:
        self.engine: Engine = db_engine if db_engine is not None else get_engine()
        self.model_cls: type[T] = model_cls
        self.name: str = str(model_cls.__tablename__)
        logger.info(f"Initializing table {self.name}")

    @contextmanager
    def session(self) -> Generator[Session]:
        with session_scope(self.engine) as session:
            yield session

    def get_by_id(self, record_id: str) -> T | None:
        with self.session() as session:
            return session.get(self.model_cls, record_id)

    def find_one(self, **where: object) -> T | None:
        with self.session() as session:
            return session.scalars(select(self.model_cls).filter_by(**where)).first()

    def find_all(self, **where: object) -> list[T]:
        with self.session() as session:
            return list(session.scalars(select(self.model_cls).filter_by(**where)).all())

    def get_table(self) -> list[T]:
        return self.find_all()

    def delete_by_id(self, record_id: str) -> bool:
        logger.info(f"Deleting record '{record_id}' on table {self.name}")
        with self.session() as session:
            row = session.get(self.model_cls, record_id)
            if row is None:
                return False
            session.delete(row)
            return True

    def delete_where(self, **where: object) -> int:
        logger.info(f"Deleting records matching {where} on table {self.name}")
        with self.session() as session:
            result = session.execute(delete(self.model_cls).filter_by(**where))
            return rowcount(result)
