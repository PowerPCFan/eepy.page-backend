from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base

if TYPE_CHECKING:
    from database.models.user import User


class Invite(Base):
    __tablename__ = "invites"

    code: Mapped[str] = mapped_column(primary_key=True)
    creator_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    used: Mapped[bool] = mapped_column(default=False, index=True)
    used_by: Mapped[str | None] = mapped_column(default=None)
    used_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    created: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    creator: Mapped[User | None] = relationship(
        back_populates="invites",
        foreign_keys="[Invite.creator_id]",
        default=None,
        repr=False,
        compare=False,
    )
