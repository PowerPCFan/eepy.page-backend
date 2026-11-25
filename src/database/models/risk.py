from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from database.models.base import Base


class IPActivityModel(Base):
    __tablename__ = "ip_activity"
    __table_args__ = (Index("ix_ip_activity_ip_last_seen", "ip", "last_seen"),)

    id: Mapped[str] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(default="", index=True)
    user_id: Mapped[str] = mapped_column(default="", index=True)
    last_seen: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0", index=True)
    expires_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default_factory=lambda: datetime.now(UTC),
        index=True,
    )

    def to_dict(self) -> dict[str, Any]:
        exp_after = self.expires_after
        if exp_after is not None and exp_after.tzinfo is None:
            exp_after = exp_after.replace(tzinfo=UTC)
        return {
            "_id": self.id,
            "ip": self.ip,
            "user_id": self.user_id,
            "last_seen": self.last_seen,
            "expires_after": exp_after,
        }


class RecentLogoutModel(Base):
    __tablename__ = "recent_logouts"

    id: Mapped[int | None] = mapped_column(primary_key=True, autoincrement=True, init=False, default=None)
    user_id: Mapped[str] = mapped_column(default="", index=True)
    ip: Mapped[str | None] = mapped_column(default=None, index=True)
    device_id: Mapped[str | None] = mapped_column(default=None, index=True)
    time: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0", index=True)
    expires_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default_factory=lambda: datetime.now(UTC),
        index=True,
    )

    def to_dict(self) -> dict[str, Any]:
        exp_after = self.expires_after
        if exp_after is not None and exp_after.tzinfo is None:
            exp_after = exp_after.replace(tzinfo=UTC)
        return {
            "_id": self.id,
            "user_id": self.user_id,
            "ip": self.ip,
            "device_id": self.device_id,
            "time": self.time,
            "expires_after": exp_after,
        }
