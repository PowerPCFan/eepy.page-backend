import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlmodel import col, delete

from database.session import session_scope
from models.tables import (
    AltLink,
    IPActivityModel,
    RecentLogoutModel,
    SessionModel,
    User,
    VerificationCode,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")


def purge_expired_records(engine: "Engine | None" = None) -> dict[str, int]:
    now = datetime.now(UTC)
    now_epoch = round(now.timestamp())
    counts: dict[str, int] = {}

    with session_scope(engine) as session:
        counts["sessions"] = int(
            session.exec(delete(SessionModel).where(col(SessionModel.expires) <= now)).rowcount or 0,  # pyright: ignore[reportAttributeAccessIssue]
        )
        counts["codes"] = int(
            session.exec(delete(VerificationCode).where(col(VerificationCode.expires_after) <= now)).rowcount or 0,  # pyright: ignore[reportAttributeAccessIssue]
        )
        counts["ip_activity"] = int(
            session.exec(delete(IPActivityModel).where(col(IPActivityModel.expires_after) <= now)).rowcount or 0,  # pyright: ignore[reportAttributeAccessIssue]
        )
        counts["recent_logouts"] = int(
            session.exec(delete(RecentLogoutModel).where(col(RecentLogoutModel.expires_after) <= now)).rowcount or 0,  # pyright: ignore[reportAttributeAccessIssue]
        )
        counts["alt_links"] = int(
            session.exec(
                delete(AltLink).where(
                    col(AltLink.permanent) == False,
                    col(AltLink.expires_at).is_not(None),
                    col(AltLink.expires_at) <= now_epoch,
                ),
            ).rowcount
            or 0,  # pyright: ignore[reportAttributeAccessIssue]
        )
        counts["deleted_banned_users"] = int(
            session.exec(
                delete(User).where(
                    col(User.banned) == True,
                    col(User.deleted_in).is_not(None),
                    col(User.deleted_in) <= now,
                ),
            ).rowcount
            or 0,  # pyright: ignore[reportAttributeAccessIssue]
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
