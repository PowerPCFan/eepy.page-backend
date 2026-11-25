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

    with session_scope(engine) as session:
        counts["sessions"] = rowcount(session.execute(delete(SessionModel).where(SessionModel.expires <= now)))
        counts["codes"] = rowcount(
            session.execute(delete(VerificationCode).where(VerificationCode.expires_after <= now)),
        )
        counts["ip_activity"] = rowcount(
            session.execute(delete(IPActivityModel).where(IPActivityModel.expires_after <= now)),
        )
        counts["recent_logouts"] = rowcount(
            session.execute(delete(RecentLogoutModel).where(RecentLogoutModel.expires_after <= now)),
        )
        counts["alt_links"] = rowcount(
            session.execute(
                delete(AltLink).where(
                    AltLink.permanent.is_(False),
                    AltLink.expires_at.is_not(None),
                    AltLink.expires_at <= now_epoch,
                ),
            ),
        )
        counts["deleted_banned_users"] = rowcount(
            session.execute(
                delete(User).where(
                    User.banned.is_(True),
                    User.deleted_in.is_not(None),
                    User.deleted_in <= now,
                ),
            ),
        )

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
