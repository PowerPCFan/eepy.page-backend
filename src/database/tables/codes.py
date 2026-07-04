import contextlib
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import NotRequired, TypedDict

from pymongo import MongoClient

from database.table import Table
from security.encryption import Encryption

logger: logging.Logger = logging.getLogger("eepy.page")

EXPIRE_TIME = 45 * 60


class GenericCodeFormat(TypedDict):
    account: str
    expire: int


class CodeStatus(TypedDict):
    valid: bool
    account: NotRequired[str]


class Codes(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "codes")

        self.verification_codes: dict[str, GenericCodeFormat] = {}
        self.recovery_codes: dict[str, GenericCodeFormat] = {}
        self.deletion_codes: dict[str, GenericCodeFormat] = {}
        self.link_codes: dict[str, GenericCodeFormat] = {}

        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))

        self.__sync_codes()

    def __sync_codes(self) -> None:
        logger.info("Syncing codes...")
        codes: list[dict] = self.get_table()

        codes_found: int = 0
        for code in codes:
            id: str = code["_id"]  # noqa: A001
            getattr(self, f"{code['type']}_codes")[id] = {
                "account": code["account"],
                "expire": code["expire"],
            }

            codes_found += 1

        logger.info(f"Synced {codes_found} codes")

    def create_code(self, type: str, target_username: str) -> str:  # noqa: A002
        logger.info(f"Creating code with the type of {type}")
        code: str = Encryption.generate_random_string(16)

        local_code: dict = {}

        if type == "verification":
            self.verification_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time()) + EXPIRE_TIME,
            }
            local_code = self.verification_codes

        elif type == "deletion":
            self.deletion_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time()) + EXPIRE_TIME,
            }
            local_code = self.deletion_codes

        elif type == "recovery":
            self.recovery_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time()) + EXPIRE_TIME,
            }
            local_code = self.recovery_codes
        elif type == "link":
            self.link_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time() + EXPIRE_TIME),
            }
            local_code = self.link_codes

        else:
            msg = "Code type is not valid"
            raise ValueError(msg)

        self.insert_document(
            {
                "_id": code,
                "type": type,
                "expire": local_code[code]["expire"],
                "account": local_code[code]["account"],
                "expiresAfter": datetime.now(UTC) + timedelta(seconds=EXPIRE_TIME),
            },
        )
        logger.info(f"Created code for user {target_username}")

        self.delete_in_time("expiresAfter")

        return code

    def is_valid(self, code: str, type: str) -> CodeStatus:  # noqa: A002
        code_result = getattr(self, f"{type}_codes").get(code)

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

    def delete_code(self, code: str, type: str) -> None:  # noqa: A002
        logger.info(f"Deleting code {code}")
        if type == "verification":
            with contextlib.suppress(Exception):
                self.verification_codes[code]["expire"] = round(time.time() - 600)
        self.table.delete_one({"_id": code})
