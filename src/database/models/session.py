from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from database.models.base import Base


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(default="", index=True)
    owner_hash: Mapped[str | None] = mapped_column(default=None, index=True)
    type: Mapped[str] = mapped_column(default="access", index=True)
    created: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    expires: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default_factory=lambda: datetime.now(UTC),
        index=True,
    )
    agent: Mapped[str] = mapped_column(default="")
    ip: Mapped[str] = mapped_column(default="")
    parent: Mapped[str | None] = mapped_column(default=None, index=True)
    manual_login: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=None)

    def to_public_dict(self) -> dict[str, Any]:
        expires_dt = self.expires
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=UTC)
        payload: dict[str, Any] = {
            "_id": self.id,
            "owner": self.owner,
            "type": self.type,
            "created": self.created,
            "expires": round(expires_dt.timestamp()),
            "agent": self.agent,
            "ip": self.ip,
        }
        if self.owner_hash:
            payload["owner_hash"] = self.owner_hash
        if self.parent:
            payload["parent"] = self.parent
        if self.manual_login is not None:
            payload["manual_login"] = self.manual_login
        return payload


class VerificationCode(Base):
    __tablename__ = "codes"

    id: Mapped[str] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(index=True)
    account: Mapped[str] = mapped_column(default="")
    expire: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0", index=True)
    expires_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default_factory=lambda: datetime.now(UTC),
        index=True,
    )
