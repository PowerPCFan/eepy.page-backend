from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base

if TYPE_CHECKING:
    from database.models.user import User


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    string: Mapped[str] = mapped_column(default="")
    perms: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")
    domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")
    comment: Mapped[str] = mapped_column(default="")

    user: Mapped[User | None] = relationship(back_populates="api_keys", default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "string": self.string,
            "perms": list(self.perms or []),
            "domains": list(self.domains or []),
            "comment": self.comment,
        }
