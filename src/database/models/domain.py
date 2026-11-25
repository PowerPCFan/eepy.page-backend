from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import JSON, BigInteger, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base
from dns_.types import get_record_type

if TYPE_CHECKING:
    from database.models.user import User
    from server.models.domain import DomainRecord


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("user_id", "name", "type", name="uq_domains_user_name_type"),
        Index("ix_domains_name_type", "name", "type"),
    )

    id: Mapped[int | None] = mapped_column(primary_key=True, autoincrement=True, init=False, default=None)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(index=True)
    type: Mapped[str] = mapped_column(index=True)
    ip: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")
    registered: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    user: Mapped[User | None] = relationship(back_populates="domains", default=None)

    def to_record(self) -> DomainRecord:
        return {
            "name": self.name,
            "type": get_record_type(self.type),
            "ip": list(self.ip) if isinstance(self.ip, list) else [str(self.ip)],
            "registered": self.registered,
        }
