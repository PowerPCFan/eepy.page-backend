from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import JSON, BigInteger
from sqlalchemy.orm import Mapped, mapped_column

from database.models.base import Base


class Reward(Base):
    __tablename__ = "rewards"

    id: Mapped[str] = mapped_column(primary_key=True)
    created: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    mappings: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default_factory=dict, server_default="{}")
    associated_email: Mapped[str] = mapped_column(default="")
    email_hash: Mapped[str] = mapped_column(default="", index=True)
    used: Mapped[bool] = mapped_column(default=False, index=True)
    used_by: Mapped[str | None] = mapped_column(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "_id": self.id,
            "created": self.created,
            "mappings": dict(self.mappings) if isinstance(self.mappings, Mapping) else {},
            "associated_email": self.associated_email,
            "email_hash": self.email_hash,
            "used": self.used,
            "used_by": self.used_by,
        }
