import logging
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, NotRequired, TypedDict

from sqlalchemy import delete

from config.env import Environment
from database.models import VerificationCode
from database.table import Table
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

EXPIRE_TIME = 45 * 60
VALID_CODE_TYPES = frozenset({"verification", "deletion", "recovery"})


class CodeStatus(TypedDict):
    valid: bool
    account: NotRequired[str]


class Codes(Table[VerificationCode]):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, VerificationCode)
        self.encryption: Encryption = Encryption(Environment.enc_key())

    def create_code(self, type: str, target_username: str) -> str:
        logger.info(f"Creating code with the type of {type}")
        if type not in VALID_CODE_TYPES:
            msg = "Code type is not valid"
            raise ValueError(msg)

        code: str = Encryption.generate_random_string(16)
        encrypted_account = self.encryption.encrypt(target_username)
        expire_ts = round(time.time()) + EXPIRE_TIME
        expires_after = datetime.now(UTC) + timedelta(seconds=EXPIRE_TIME)

        with self.session() as session:
            session.add(
                VerificationCode(
                    id=code,
                    type=type,
                    account=encrypted_account,
                    expire=expire_ts,
                    expires_after=expires_after,
                ),
            )

        logger.info(f"Created {type} code for user {target_username}")
        return code

    def is_valid(self, code: str, type: str) -> CodeStatus:
        if type not in VALID_CODE_TYPES:
            return {"valid": False}

        with self.session() as session:
            row = session.get(VerificationCode, code)
            if row is None or row.type != type:
                return {"valid": False}

            if row.expire < round(time.time()):
                return {
                    "valid": False,
                    "account": self.encryption.decrypt(row.account),
                }

            return {
                "valid": True,
                "account": self.encryption.decrypt(row.account),
            }

    def delete_code(self, code: str, type: str) -> None:
        if type not in VALID_CODE_TYPES:
            return
        logger.info(f"Deleting {type} code")
        with self.session() as session:
            session.execute(
                delete(VerificationCode).where(
                    VerificationCode.id == code,
                    VerificationCode.type == type,
                ),
            )
