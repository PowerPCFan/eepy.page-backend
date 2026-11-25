import logging
import re
import time
from typing import TYPE_CHECKING, TypedDict, cast

from sqlalchemy import select

from database.exceptions import ConflictingReferralCode, UserNotExistError
from database.models import Referral, ReferralRedemption, User, UserPermissions
from database.table import Table

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from database.tables.users import Users, UserType

logger: logging.Logger = logging.getLogger("eepy.page")


class ReferralType(TypedDict):
    _id: str
    owner: str
    users: list[str]
    created: int


class Referrals(Table):
    def __init__(self, db_engine: "Engine | None", users: "Users") -> None:
        super().__init__(db_engine, "referrals")
        self.users: Users = users

    def insert(self, document: ReferralType) -> None:
        return super().insert_document(document)

    def create(self, user_id: str, requested_code: str) -> None:
        requested_code = requested_code.lower()
        logger.info("Creating referral code")
        if len(requested_code) < 3 or len(requested_code) > 50:  # noqa: PLR2004
            msg = f"requested code is too long or too short! {requested_code}"
            raise ValueError(msg)

        if not re.fullmatch(r"[a-z0-9-]+", requested_code):
            msg = "Invalid code regex!"
            raise ValueError(msg)

        lookup_request_code: str = self.users.encryption.sha256(requested_code)

        with self.session() as session:
            user = session.get(User, user_id)
            if user is None or user.banned:
                msg = "User does not exist!"
                raise UserNotExistError(msg)

            if user.referral_code:
                msg = "User already has a referral code"
                raise ValueError(msg)

            existing = session.get(Referral, lookup_request_code)
            if existing is not None:
                msg = "Referral code already exists!"
                raise ConflictingReferralCode(msg)

            session.add(
                Referral(
                    id=lookup_request_code,
                    owner=user_id,
                    created=round(time.time()),
                ),
            )
            user.referral_code = requested_code
            session.add(user)

    def check(self, referral_code: str) -> bool:
        referral_code = referral_code.lower()
        lookup_request_code: str = self.users.encryption.sha256(referral_code)
        with self.session() as session:
            return session.get(Referral, lookup_request_code) is not None

    def use(self, user: "UserType", referral_code: str) -> None:
        referral_code = referral_code.lower()
        logger.info(f"Using referral {referral_code}")
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        with self.session() as session:
            referral = session.get(Referral, lookup_request_code)
            if referral is None:
                logger.warning("Referral does not exist!")
                msg = "Referral does not exist!"
                raise ValueError(msg)

            owner = session.get(User, referral.owner)
            if owner is None or owner.banned:
                logger.warning("Referral owner does not exist!")
                msg = "Referral owner does not exist!"
                raise ValueError(msg)

            new_referred_count = (owner.referred_count or 0) + 1
            owner.referred_count = new_referred_count

            # Grant 1 extra domain for every 2 verified referrals, capped at 5 bonus domains (10 referrals)
            if new_referred_count <= 10 and new_referred_count % 2 == 0:  # noqa: PLR2004
                logger.info(
                    f"Granting extra domain to referral owner {referral.owner} (referred count: {new_referred_count})",
                )
                perms = owner.permissions_rel or UserPermissions(user_id=owner.id)
                perms.max_domains = int(perms.max_domains) + 1
                owner.permissions_rel = perms

            session.add(
                ReferralRedemption(
                    referral_id=referral.id,
                    referred_user_id=user["_id"],
                    created_at=round(time.time()),
                ),
            )

            session.add(owner)

    def get_users(self, referral_code: str) -> list["UserType"]:
        referral_code = referral_code.lower()
        with self.session() as session:
            rows = session.scalars(select(User).where(User.referred_by == referral_code)).all()
            return [cast("UserType", row.to_dict()) for row in rows]
