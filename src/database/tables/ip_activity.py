import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypedDict

from sqlalchemy import or_, select

from database.models import IPActivityModel, RecentLogoutModel
from database.table import Table

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

IP_ACTIVITY_TTL_SECONDS = 60 * 86400
LOGOUT_VELOCITY_WINDOW_SECONDS = 120

EXPIRES_FIELD = "expires_after"
BACKFILL_BATCH_SIZE = 1000
DEVICE_ID_REGEX: re.Pattern[str] = re.compile(r"\A[A-Za-z0-9_.:-]{4,128}\Z")


def normalize_device_id(device_id: str | None) -> str | None:
    if not device_id or not isinstance(device_id, str):
        return None
    cleaned = device_id.strip()
    if not DEVICE_ID_REGEX.fullmatch(cleaned):
        return None
    return cleaned


class IPActivityType(TypedDict):
    _id: str
    ip: str
    user_id: str
    last_seen: int
    expires_after: datetime


class RecentLogoutType(TypedDict):
    user_id: str
    ip: str | None
    device_id: str | None
    time: int
    expires_after: datetime


def expiry_from_epoch(epoch_seconds: float, ttl_seconds: int) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, UTC) + timedelta(seconds=ttl_seconds)


class IPActivity(Table):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, "ip_activity")

    def record_activity(self, ip: str, user_id: str, timestamp: int) -> None:
        if not ip:
            return
        try:
            doc_id = f"{ip}_{user_id}"
            expires_at = expiry_from_epoch(timestamp, IP_ACTIVITY_TTL_SECONDS)
            with self.session() as session:
                existing = session.get(IPActivityModel, doc_id)
                if existing is not None:
                    existing.ip = ip
                    existing.user_id = user_id
                    existing.last_seen = timestamp
                    existing.expires_after = expires_at
                    session.add(existing)
                else:
                    session.add(
                        IPActivityModel(
                            id=doc_id,
                            ip=ip,
                            user_id=user_id,
                            last_seen=timestamp,
                            expires_after=expires_at,
                        ),
                    )
        except Exception:
            logger.exception("Failed to record activity in ip_activity table")

    def find_recent_shared_ip(self, ip: str, user_id: str, since_timestamp: int) -> dict[str, Any] | None:
        if not ip:
            return None
        with self.session() as session:
            stmt = select(IPActivityModel).where(
                IPActivityModel.ip == ip,
                IPActivityModel.user_id != user_id,
                IPActivityModel.last_seen > since_timestamp,
            )
            row = session.scalars(stmt).first()
            return row.to_dict() if row is not None else None


class RecentLogouts(Table):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, "recent_logouts")

    def record_logout(self, user_id: str, ip: str | None, device_id: str | None, timestamp: int) -> None:
        clean_ip = ip.strip() if ip else None
        clean_device = normalize_device_id(device_id)
        if not clean_ip and not clean_device:
            return
        try:
            with self.session() as session:
                session.add(
                    RecentLogoutModel(
                        user_id=user_id,
                        ip=clean_ip or None,
                        device_id=clean_device,
                        time=timestamp,
                        expires_after=expiry_from_epoch(timestamp, LOGOUT_VELOCITY_WINDOW_SECONDS),
                    ),
                )
        except Exception:
            logger.exception("Failed to record logout in recent_logouts table")

    def find_recent_switches(
        self,
        user_id: str,
        ip: str | None,
        device_id: str | None,
        since_timestamp: int,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        clean_ip = ip.strip() if ip else ""
        clean_device = normalize_device_id(device_id)
        conditions = []
        if clean_ip:
            conditions.append(RecentLogoutModel.ip == clean_ip)
        if clean_device:
            conditions.append(RecentLogoutModel.device_id == clean_device)
        if not conditions:
            return []

        with self.session() as session:
            stmt = (
                select(RecentLogoutModel)
                .where(
                    or_(*conditions),
                    RecentLogoutModel.user_id != user_id,
                    RecentLogoutModel.time >= since_timestamp,
                )
                .order_by(RecentLogoutModel.time.desc())
                .limit(limit)
            )
            rows = session.scalars(stmt).all()
            return [row.to_dict() for row in rows]
