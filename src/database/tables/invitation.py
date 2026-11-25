import logging
import time
from typing import TYPE_CHECKING

from database.exceptions import InviteException, UserNotExistError
from database.models import Invite, User
from database.table import Table
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

INVITE_LENGTH: int = 16

logger: logging.Logger = logging.getLogger("eepy.page")


class Invites(Table[Invite]):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, Invite)

    def is_valid(self, code: str) -> bool:
        logger.info(f"Checking invite {code}")

        if len(code) != INVITE_LENGTH:
            return False

        with self.session() as session:
            invite = session.get(Invite, code)
            if invite is None:
                logger.info("Invite not found")
                return False

            holder = session.get(User, invite.creator_id)
            if holder is None or holder.banned:
                logger.info("Invite holder does not exist...")
                return False

            return not invite.used

    def create(self, user_id: str) -> str:
        logger.info("Creating invite")
        invite_code: str = Encryption.generate_random_string(INVITE_LENGTH)

        with self.session() as session:
            user = session.get(User, user_id)
            if user is None or user.banned:
                msg = "User does not exist!"
                raise UserNotExistError(msg)

            if len(user.invites or []) >= 3:  # noqa: PLR2004
                msg = "User has made too many invites"
                raise InviteException(msg)

            session.add(
                Invite(
                    code=invite_code,
                    creator_id=user_id,
                    used=False,
                    used_by=None,
                    used_at=None,
                    created=round(time.time()),
                ),
            )

        return invite_code

    def use(self, user_id: str, invite_code: str) -> bool:
        if not self.is_valid(invite_code):
            msg = "Invite is not valid"
            raise InviteException(msg)

        with self.session() as session:
            invite = session.get(Invite, invite_code)
            if invite is None:
                msg = "Invite is not valid"
                raise InviteException(msg)
            invite.used = True
            invite.used_by = user_id
            invite.used_at = round(time.time())
            session.add(invite)

        return True
