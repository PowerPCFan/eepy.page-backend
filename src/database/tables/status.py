import logging
import time
from typing import TypedDict

from pymongo import MongoClient

from database.table import Table
from security.encryption import Encryption

logger: logging.Logger = logging.getLogger("eepy.page")


class StatusType(TypedDict):
    _id: str
    time: float
    message: str
    active: bool


class Status(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "status")

    def get(self) -> StatusType | None:
        logger.info("Getting active status")
        return self.find_item({"active": True}) # pyright: ignore[reportReturnType]

    def set(self, message: str) -> None:
        self.modify_document(
            filter={"active": True},
            operation="$set",
            key="active",
            value=False,
            create_if_not_exist=False,
            ignore_no_matches=True,
        )
        self.insert_document(
            {
                "_id": Encryption.generate_random_string(16),
                "time": time.time(),
                "message": message,
                "active": True,
            },
        )
