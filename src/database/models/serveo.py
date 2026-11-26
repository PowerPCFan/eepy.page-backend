from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base

if TYPE_CHECKING:
    from database.models.user import User


class ServeoTunnel(Base):
    __tablename__ = "serveo_tunnels"

    id: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    serveo_auth_record: Mapped[str] = mapped_column(default="")
    ssh_fingerprint: Mapped[str] = mapped_column(default="")
    subdomain: Mapped[str] = mapped_column(default="")
    hostname: Mapped[str] = mapped_column(default="", index=True)
    service: Mapped[str] = mapped_column(default="")
    local_port: Mapped[int] = mapped_column(default=80)
    command: Mapped[str] = mapped_column(default="")
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    user: Mapped[User | None] = relationship(back_populates="tunnels", default=None, repr=False, compare=False)
