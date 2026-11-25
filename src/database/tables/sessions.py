import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import delete, or_, select

from database.models import SessionModel
from database.table import Table

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger = logging.getLogger("eepy.page")


class Sessions(Table[SessionModel]):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, SessionModel)

    def add_session(  # noqa: PLR0913
        self,
        *,
        uid: str,
        user_id: str,
        type: Literal["access", "refresh"],
        expires: int,
        user_agent: str,
        ip: str,
        parent: str | None = None,
    ) -> None:
        with self.session() as session:
            session_obj = SessionModel(
                id=uid,
                owner=user_id,
                type=type,
                created=round(time.time()),
                expires=datetime.fromtimestamp(expires, UTC),
                agent=user_agent,
                ip=ip,
                parent=parent,
            )
            session.merge(session_obj)

    @staticmethod
    def _is_expired(expires: datetime) -> bool:
        exp = expires.replace(tzinfo=UTC) if expires.tzinfo is None else expires
        return exp <= datetime.now(UTC)

    def get_session(self, uid: str) -> SessionModel | None:
        with self.session() as session:
            row = session.get(SessionModel, uid)
            if row is None:
                return None
            if self._is_expired(row.expires):
                session.delete(row)
                return None
            return row

    def set_manual_login(self, refresh_uid: str, user_id: str, metadata: dict[str, Any]) -> None:
        with self.session() as session:
            row = session.get(SessionModel, refresh_uid)
            if row is not None:
                row.manual_login = {"user_id": user_id, "metadata": metadata}
                session.add(row)

    def delete_session_pair(self, refresh_uid: str) -> bool:
        """Deletes both the refresh and access token for said sesison"""
        logger.info("Marking session as disabled")

        if len(refresh_uid) < 30:  # noqa: PLR2004
            logger.error(f"Small refresh token passed {len(refresh_uid)}")
            return False

        with self.session() as session:
            stmt = select(SessionModel).where(
                or_(
                    SessionModel.id == refresh_uid,
                    SessionModel.parent == refresh_uid,
                ),
            )
            rows = list(session.scalars(stmt).all())
            if not rows:
                logger.warning("Failed to delete session as there werent any matches")
                logger.debug(refresh_uid)
                return False

            for row in rows:
                session.delete(row)

            logger.info(f"Deleted {len(rows)} sessions")
            return True

    def consume_refresh_session(self, refresh_uid: str) -> SessionModel | None:
        if len(refresh_uid) < 30:  # noqa: PLR2004
            logger.error(f"Small refresh token passed {len(refresh_uid)}")
            return None

        with self.session() as session:
            stmt = select(SessionModel).where(
                SessionModel.id == refresh_uid,
                SessionModel.type == "refresh",
            )
            target = session.scalars(stmt).first()
            if target is None:
                return None

            expired = self._is_expired(target.expires)
            session.delete(target)
            session.execute(
                delete(SessionModel).where(SessionModel.parent == refresh_uid),
            )
            if expired:
                return None
            return target
