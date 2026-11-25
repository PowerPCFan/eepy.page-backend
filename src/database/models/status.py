from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.orm import Mapped, mapped_column

from database.models.base import Base

if TYPE_CHECKING:
    from database.tables.status import StatusType


class StatusModel(Base):
    __tablename__ = "status"

    id: Mapped[str] = mapped_column(primary_key=True)
    time: Mapped[float] = mapped_column(default=0.0)
    message: Mapped[str] = mapped_column(default="")
    active: Mapped[bool] = mapped_column(default=True, index=True)

    def to_dict(self) -> StatusType:
        return {
            "_id": self.id,
            "time": self.time,
            "message": self.message,
            "active": self.active,
        }
