import logging
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

from sqlalchemy.orm.attributes import flag_modified

from database.models import Reward, User, UserOwnedTLD
from database.table import Table
from database.tables.users import Users
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")


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
        for key, value in extra_fields.items():
            key_str = str(key)
            if hasattr(user, key_str) and key_str not in {"id", "extra_data"}:
                setattr(user, key_str, value)
            else:
                extra[key_str] = value
        user.extra_data = extra
        flag_modified(user, "extra_data")

    def use(self, user_id: str, code: str) -> bool:
        with self.session() as session:
            reward = session.get(Reward, code)
            if reward is None:
                logger.warning("Code doesn't exist")
                return False

            if reward.used:
                logger.warning("Code has already been used")
                return False

            user = session.get(User, user_id)
            if user is not None:
                mappings = reward.mappings or {}
                grant_tlds = mappings.get("grant_tlds")
                if isinstance(grant_tlds, list):
                    for tld in grant_tlds:
                        tld_str = str(tld).strip()
                        if tld_str and session.get(UserOwnedTLD, (user_id, tld_str)) is None:
                            session.add(UserOwnedTLD(user_id=user_id, tld=tld_str))

                grant_credits = mappings.get("credits")
                if isinstance(grant_credits, int):
                    user.credits += grant_credits

                extra_fields = mappings.get("fields")
                if isinstance(extra_fields, Mapping) and extra_fields:
                    self._apply_extra_fields(user, extra_fields)

                session.add(user)

            reward.used = True
            reward.used_by = user_id
            session.add(reward)
            return True
