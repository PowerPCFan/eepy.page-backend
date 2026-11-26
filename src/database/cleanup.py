import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete

from database.models import (
    AltLink,
    IPActivityModel,
    RecentLogoutModel,
    SessionModel,
    User,
    VerificationCode,
)
from database.session import rowcount, session_scope

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")


def purge_expired_records(engine: "Engine | None" = None) -> dict[str, int]:
    now = datetime.now(UTC)
    now_epoch = round(now.timestamp())
    counts: dict[str, int] = {}

    statements = [
        ("sessions", delete(SessionModel).where(SessionModel.expires <= now)),
        ("codes", delete(VerificationCode).where(VerificationCode.expires_after <= now)),
        ("ip_activity", delete(IPActivityModel).where(IPActivityModel.expires_after <= now)),
        ("recent_logouts", delete(RecentLogoutModel).where(RecentLogoutModel.expires_after <= now)),
        (
            "alt_links",
            delete(AltLink).where(
                AltLink.permanent.is_(False),
                AltLink.expires_at.is_not(None),
                AltLink.expires_at <= now_epoch,
            ),
        ),
        (
            "deleted_banned_users",
            # Deleting from users cascades to all user-owned child tables in Postgres (ON DELETE CASCADE).
            delete(User).where(
                User.banned.is_(True),
                User.deleted_in.is_not(None),
                User.deleted_in <= now,
            ),
        ),
    ]

    for label, stmt in statements:
        try:
            with session_scope(engine) as session:
                counts[label] = rowcount(session.execute(stmt))
        except Exception:
            logger.exception("Failed to purge expired rows for %s", label)
            counts[label] = 0

    total = sum(counts.values())
    if total > 0:
        logger.info("Purged %d expired database records: %s", total, counts)
    else:
        logger.debug("purge_expired_records: no expired rows found")

    return counts


def start_expired_cleanup_loop(engine: "Engine | None" = None, interval: int = 600) -> None:
    logger.info("Starting expired database record cleanup loop (every %ds)", interval)
    while True:
        try:
            purge_expired_records(engine)
        except Exception:
            logger.exception("Failed during expired database record cleanup")
        time.sleep(interval)
