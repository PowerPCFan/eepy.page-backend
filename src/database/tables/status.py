import logging
import time
from typing import TYPE_CHECKING, TypedDict

from sqlalchemy import select, update

from database.models import StatusModel
from database.table import Table
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")


class StatusType(TypedDict):
    _id: str
    time: float
    message: str
    active: bool


class Status(Table):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, "status")

    def get(self) -> StatusType | None:
        logger.info("Getting active status")
        with self.session() as session:
            row = session.scalars(select(StatusModel).where(StatusModel.active.is_(True))).first()
            if row is None:
                return None
            return row.to_dict()

    def set(self, message: str) -> None:
        with self.session() as session:
            session.execute(
                update(StatusModel).where(StatusModel.active.is_(True)).values(active=False),
            )
            new_status = StatusModel(
                id=Encryption.generate_random_string(16),
                time=time.time(),
                message=message,
                active=True,
            )
            session.add(new_status)

    def clear(self) -> None:
        with self.session() as session:
            session.execute(
                update(StatusModel).where(StatusModel.active.is_(True)).values(active=False),
            )
