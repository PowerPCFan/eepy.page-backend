from __future__ import annotations

from typing import TYPE_CHECKING, Any

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

    user: Mapped[User | None] = relationship(back_populates="tunnels", default=None)

    def to_record(self) -> dict[str, Any]:
        return {
            "_id": self.id,
            "id": self.id,
            "user_id": self.user_id,
            "serveo_auth_record": self.serveo_auth_record,
            "ssh_fingerprint": self.ssh_fingerprint,
            "subdomain": self.subdomain,
            "hostname": self.hostname,
            "service": self.service,
            "local_port": self.local_port,
            "command": self.command,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_embedded_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "serveo_auth_record": self.serveo_auth_record,
            "ssh_fingerprint": self.ssh_fingerprint,
            "subdomain": self.subdomain,
            "hostname": self.hostname,
            "service": self.service,
            "local_port": self.local_port,
            "command": self.command,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
