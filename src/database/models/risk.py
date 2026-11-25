from __future__ import annotations

from datetime import UTC, datetime

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


class RecentLogoutModel(Base):
    __tablename__ = "recent_logouts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, init=False)
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
