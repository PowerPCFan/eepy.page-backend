import logging
import re
import time
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from database.exceptions import ConflictingReferralCode, UserNotExistError
from database.models import Referral, ReferralRedemption, User, UserPermissions
from database.table import Table

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from database.tables.users import Users

logger: logging.Logger = logging.getLogger("eepy.page")


class Referrals(Table[Referral]):
    def __init__(self, db_engine: "Engine | None", users: "Users") -> None:
        super().__init__(db_engine, Referral)
        self.users: Users = users

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
            user = session.scalars(select(User).where(User.id == user_id).with_for_update()).first()
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
            try:
                session.flush()
            except IntegrityError as exc:
                msg = "Referral code already exists!"
                raise ConflictingReferralCode(msg) from exc

    def check(self, referral_code: str) -> bool:
        referral_code = referral_code.lower()
        lookup_request_code: str = self.users.encryption.sha256(referral_code)
        with self.session() as session:
            stmt = (
                select(Referral.id)
                .join(User, User.id == Referral.owner)
                .where(Referral.id == lookup_request_code, User.banned.is_(False))
            )
            return session.scalar(stmt) is not None

    def use(self, user: User, referral_code: str) -> None:
        referral_code = referral_code.lower()
        logger.info(f"Using referral {referral_code}")
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        with self.session() as session:
            referral = session.get(Referral, lookup_request_code)
            if referral is None:
                logger.warning("Referral does not exist!")
                msg = "Referral does not exist!"
                raise ValueError(msg)

            if referral.owner == user.id:
                msg = "Cannot redeem own referral code"
                raise ValueError(msg)

            owner = session.scalars(select(User).where(User.id == referral.owner).with_for_update()).first()
            if owner is None or owner.banned:
                logger.warning("Referral owner does not exist!")
                msg = "Referral owner does not exist!"
                raise ValueError(msg)

            existing_redemption = session.scalar(
                select(ReferralRedemption.id).where(ReferralRedemption.referred_user_id == user.id),
            )
            if existing_redemption is not None:
                msg = "User has already redeemed a referral code"
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
                    referred_user_id=user.id,
                    created_at=round(time.time()),
                ),
            )

            session.add(owner)

    def get_users(self, referral_code: str) -> list[User]:
        referral_code = referral_code.lower()
        with self.session() as session:
            return list(session.scalars(select(User).where(User.referred_by == referral_code)).all())
