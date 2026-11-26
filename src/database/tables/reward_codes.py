import logging
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm.attributes import flag_modified

from database.models import Reward, User, UserOwnedTLD, UserPermissions
from database.table import Table
from database.tables.users import Users
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

_ALLOWED_SCALAR_USER_FIELDS = frozenset({"credits", "lang"})


class Rewards(Table[Reward]):
    def __init__(self, db_engine: "Engine | None", users: Users) -> None:
        self.encryption: Encryption = users.encryption
        self.users: Users = users
        super().__init__(db_engine, Reward)

    def create(self, email: str, rewards: dict) -> str:
        """Creates a new reward code"""
        clean_email = email.strip()
        code_id = Encryption.generate_random_string(16)
        with self.session() as session:
            reward_obj = Reward(
                id=code_id,
                created=round(time.time()),
                mappings=dict(rewards),
                associated_email=self.encryption.encrypt(clean_email),
                email_hash=self.encryption.hash_email(clean_email),
                used=False,
                used_by=None,
            )
            session.add(reward_obj)

        return code_id

    @staticmethod
    def _apply_extra_fields(user: User, extra_fields: Mapping[object, object]) -> None:
        extra = dict(user.extra_data or {})
        extra_changed = False
        for key, value in extra_fields.items():
            key_str = str(key)
            if key_str == "permissions.limits.max_domains" and isinstance(value, int) and not isinstance(value, bool):
                perms = user.permissions_rel or UserPermissions(user_id=user.id)
                perms.max_domains = value
                user.permissions_rel = perms
            elif (
                key_str == "permissions.limits.max_subdomains"
                and isinstance(value, int)
                and not isinstance(value, bool)
            ):
                perms = user.permissions_rel or UserPermissions(user_id=user.id)
                perms.max_subdomains = value
                user.permissions_rel = perms
            elif key_str == "permissions.features.invite" and isinstance(value, bool):
                perms = user.permissions_rel or UserPermissions(user_id=user.id)
                perms.feature_invite = value
                user.permissions_rel = perms
            elif key_str.startswith("feature_flags."):
                flag_name = key_str.removeprefix("feature_flags.")
                if flag_name:
                    flags = dict(user.feature_flags or {})
                    flags[flag_name] = bool(value)
                    user.feature_flags = flags
                    flag_modified(user, "feature_flags")
            elif key_str in _ALLOWED_SCALAR_USER_FIELDS:
                setattr(user, key_str, value)
            else:
                extra[key_str] = value
                extra_changed = True
        if extra_changed:
            user.extra_data = extra
            flag_modified(user, "extra_data")

    def use(self, user_id: str, code: str) -> bool:
        with self.session() as session:
            reward = session.scalars(select(Reward).where(Reward.id == code).with_for_update()).first()
            if reward is None:
                logger.warning("Code doesn't exist")
                return False

            if reward.used:
                logger.warning("Code has already been used")
                return False

            user = session.scalars(select(User).where(User.id == user_id).with_for_update()).first()
            if user is None:
                logger.warning("Reward target user does not exist")
                return False

            mappings = reward.mappings or {}
            grant_tlds = mappings.get("grant_tlds")
            if isinstance(grant_tlds, list):
                unique_tlds = {str(tld).strip().lower() for tld in grant_tlds if str(tld).strip()}
                if unique_tlds:
                    session.execute(
                        pg_insert(UserOwnedTLD)
                        .values([{"user_id": user_id, "tld": tld_str} for tld_str in unique_tlds])
                        .on_conflict_do_nothing(),
                    )

            grant_credits = mappings.get("credits")
            if isinstance(grant_credits, int) and not isinstance(grant_credits, bool):
                user.credits += grant_credits

            extra_fields = mappings.get("fields")
            if isinstance(extra_fields, Mapping) and extra_fields:
                self._apply_extra_fields(user, extra_fields)

            session.add(user)

            reward.used = True
            reward.used_by = user_id
            session.add(reward)
            return True
