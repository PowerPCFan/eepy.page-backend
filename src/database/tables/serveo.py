from typing import TYPE_CHECKING

from sqlalchemy import select

from database.models import ServeoTunnel
from database.table import Table

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = ["ServeoTable"]


class ServeoTable(Table[ServeoTunnel]):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, ServeoTunnel)

    def get_tunnel(self, user_id: str, tunnel_id: str) -> ServeoTunnel | None:
        if not isinstance(user_id, str) or not isinstance(tunnel_id, str):
            return None
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            return session.scalars(stmt).first()

    def save_tunnel(self, tunnel: ServeoTunnel) -> None:
        with self.session() as session:
            session.add(tunnel)

    def update_tunnel_port(
        self,
        tunnel_id: str,
        user_id: str,
        *,
        local_port: int,
        command: str,
        updated_at: int,
    ) -> ServeoTunnel | None:
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            row = session.scalars(stmt).first()
            if row is None:
                return None
            row.service = f"localhost:{local_port}"
            row.local_port = local_port
            row.command = command
            row.updated_at = updated_at
            session.add(row)
            return row

    def remove_tunnel(self, tunnel_id: str, user_id: str) -> None:
        with self.session() as session:
            stmt = select(ServeoTunnel).where(
                ServeoTunnel.id == tunnel_id,
                ServeoTunnel.user_id == user_id,
            )
            row = session.scalars(stmt).first()
            if row is not None:
                session.delete(row)

    def tunnels(self, user_id: str) -> list[ServeoTunnel]:
        with self.session() as session:
            stmt = select(ServeoTunnel).where(ServeoTunnel.user_id == user_id)
            return list(session.scalars(stmt).all())
