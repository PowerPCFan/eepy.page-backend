from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from sqlmodel import select

from database.table import Table
from models.serveo import ServeoRecord
from models.tables import ServeoTunnel

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = ["ServeoRecord", "ServeoTable"]


class ServeoTable(Table):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, "serveo_tunnels")

    @staticmethod
    def _tunnels_from_user(user: dict[str, Any]) -> list[ServeoRecord]:
        tunnels = user.get("tunnels", [])
        return [
            cast("ServeoRecord", {**tunnel, "_id": tunnel.get("id") or tunnel.get("_id"), "user_id": user["_id"]})
            for tunnel in tunnels
        ]

    def get_tunnel(self, user_id: str, tunnel_id: str) -> ServeoRecord | None:
        if not isinstance(user_id, str) or not isinstance(tunnel_id, str):
            return None
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            row = session.exec(stmt).first()
            if row is None:
                return None
            return cast("ServeoRecord", row.to_record())

    def save_tunnel(self, document: Mapping[str, Any]) -> None:
        tunnel_id = str(document.get("_id") or document.get("id"))
        user_id = str(document["user_id"])
        with self.session() as session:
            session.add(
                ServeoTunnel(
                    id=tunnel_id,
                    user_id=user_id,
                    serveo_auth_record=str(document.get("serveo_auth_record", "")),
                    ssh_fingerprint=str(document.get("ssh_fingerprint", "")),
                    subdomain=str(document.get("subdomain", "")),
                    hostname=str(document.get("hostname", "")),
                    service=str(document.get("service", "")),
                    local_port=int(document.get("local_port", 80)),
                    command=str(document.get("command", "")),
                    created_at=int(document.get("created_at", 0)),
                    updated_at=int(document.get("updated_at", 0)),
                ),
            )

    def replace_tunnel(self, tunnel_id: str, user_id: str, tunnel: Mapping[str, Any]) -> None:
        if tunnel.get("_id") != tunnel_id:
            msg = "Tunnel ID cannot change"
            raise ValueError(msg)
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            row = session.exec(stmt).first()
            if row is None:
                return
            row.serveo_auth_record = str(tunnel.get("serveo_auth_record", row.serveo_auth_record))
            row.ssh_fingerprint = str(tunnel.get("ssh_fingerprint", row.ssh_fingerprint))
            row.subdomain = str(tunnel.get("subdomain", row.subdomain))
            row.hostname = str(tunnel.get("hostname", row.hostname))
            row.service = str(tunnel.get("service", row.service))
            row.local_port = int(tunnel.get("local_port", row.local_port))
            row.command = str(tunnel.get("command", row.command))
            row.created_at = int(tunnel.get("created_at", row.created_at))
            row.updated_at = int(tunnel.get("updated_at", row.updated_at))
            session.add(row)

    def remove_tunnel(self, tunnel_id: str, user_id: str) -> None:
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            row = session.exec(stmt).first()
            if row is not None:
                session.delete(row)

    def tunnels(self, user_id: str) -> list[ServeoRecord]:
        with self.session() as session:
            stmt = select(ServeoTunnel).where(ServeoTunnel.user_id == user_id)
            rows = session.exec(stmt).all()
            return [cast("ServeoRecord", row.to_record()) for row in rows]
