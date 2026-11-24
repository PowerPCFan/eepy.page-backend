import contextlib
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, NotRequired, TypedDict

from sqlmodel import select

from config.env import Environment
from database.table import Table
from models.tables import VerificationCode
from security.encryption import Encryption

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

EXPIRE_TIME = 45 * 60


class GenericCodeFormat(TypedDict):
    account: str
    expire: int


class CodeStatus(TypedDict):
    valid: bool
    account: NotRequired[str]


class Codes(Table):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, "codes")

        self.verification_codes: dict[str, GenericCodeFormat] = {}
        self.recovery_codes: dict[str, GenericCodeFormat] = {}
        self.deletion_codes: dict[str, GenericCodeFormat] = {}

        self.encryption: Encryption = Encryption(Environment.enc_key())

        self.__sync_codes()

    def __sync_codes(self) -> None:
        logger.info("Syncing codes...")
        codes_found: int = 0
        with self.session() as session:
            rows = session.exec(select(VerificationCode)).all()
            for row in rows:
                target_cache = getattr(self, f"{row.type}_codes", None)
                if target_cache is None:
                    logger.warning("Ignoring unknown code type %s", row.type)
                    continue

                target_cache[row.id] = {
                    "account": row.account,
                    "expire": row.expire,
                }
                codes_found += 1

        logger.info(f"Synced {codes_found} codes")

    def create_code(self, type: str, target_username: str) -> str:
        logger.info(f"Creating code with the type of {type}")
        if type not in {"verification", "deletion", "recovery"}:
            msg = "Code type is not valid"
            raise ValueError(msg)

        code: str = Encryption.generate_random_string(16)
        encrypted_account = self.encryption.encrypt(target_username)
        expire_ts = round(time.time()) + EXPIRE_TIME
        expires_after = datetime.now(UTC) + timedelta(seconds=EXPIRE_TIME)

        target_cache: dict[str, GenericCodeFormat] = getattr(self, f"{type}_codes")
        target_cache[code] = {
            "account": encrypted_account,
            "expire": expire_ts,
        }

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

        logger.info(f"Created code for user {target_username}")
        return code

    def is_valid(self, code: str, type: str) -> CodeStatus:
        target_cache: dict[str, GenericCodeFormat] | None = getattr(self, f"{type}_codes", None)
        code_result: GenericCodeFormat | None = target_cache.get(code) if target_cache is not None else None

        if code_result is None:
            with self.session() as session:
                row = session.get(VerificationCode, code)
                if row is not None and row.type == type:
                    code_result = {"account": row.account, "expire": row.expire}
                    if target_cache is not None:
                        target_cache[code] = code_result

        if code_result is None:
            return {"valid": False}

        if code_result["expire"] < round(time.time()):
            return {
                "valid": False,
                "account": self.encryption.decrypt(code_result["account"]),
            }

        return {
            "valid": True,
            "account": self.encryption.decrypt(code_result["account"]),
        }

    def delete_code(self, code: str, type: str) -> None:
        logger.info(f"Deleting code {code}")
        if type == "verification":
            with contextlib.suppress(Exception):
                self.verification_codes[code]["expire"] = round(time.time() - 600)
        else:
            target_cache: dict[str, GenericCodeFormat] | None = getattr(self, f"{type}_codes", None)
            if target_cache is not None:
                target_cache.pop(code, None)
        with self.session() as session:
            row = session.get(VerificationCode, code)
            if row is not None:
                session.delete(row)
