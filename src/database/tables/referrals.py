import logging
import re
import time
from typing import TYPE_CHECKING, TypedDict

from pymongo import MongoClient

from database.table import Table

if TYPE_CHECKING:
    from database.tables.users import Users, UserType

from database.exceptions import (
    ConflictingReferralCode,
    UserNotExistError,
)

logger: logging.Logger = logging.getLogger("eepy.page")


class ReferralType(TypedDict):
    _id: str
    owner: str
    users: list[str]
    created: int


class Referrals(Table):
    def __init__(self, mongo_client: MongoClient, users: "Users") -> None:
        super().__init__(mongo_client, "referrals")
        self.users: Users = users

    def insert(self, document: ReferralType) -> None:
        return super().insert_document(document)

    def create(self, user_id: str, requested_code: str) -> None:
        requested_code = requested_code.lower()
        logger.info("Creating referral code")
        if len(requested_code) < 3 or len(requested_code) > 50:  # noqa: PLR2004
            msg = f"requested code is too long or too short! {requested_code}"
            raise ValueError(
                msg,
            )

        if not re.fullmatch(r"[a-z0-9-]+", requested_code):
            msg = "Invalid code regex!"
            raise ValueError(msg)

        lookup_request_code: str = self.users.encryption.sha256(requested_code)

        user: UserType | None = self.users.find_user({"_id": user_id})

        if user is None:
            msg = "User does not exist!"
            raise UserNotExistError(msg)

        if user.get("referral-code") is not None:
            msg = "User already has a referral code"
            raise ValueError(msg)

        if self.find_item({"_id": lookup_request_code}) is not None:
            msg = "Referral code already exists!"
            raise ConflictingReferralCode(msg)

        self.insert(
            {
                "_id": lookup_request_code,
                "owner": user_id,
                "users": [],
                "created": round(time.time()),
            },
        )

        self.users.modify_document(
            filter={"_id": user_id},
            operation="$set",
            key="referral-code",
            value=requested_code,
        )

    def check(self, referral_code: str) -> bool:
        """Checks if referral code is valid

        :param referral_code: the referral code
        :type referral_code: str
        :return: whether the code is valid
        :rtype: bool
        """
        referral_code = referral_code.lower()
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        referral: ReferralType | None = self.find_item({"_id": lookup_request_code})  # pyright: ignore[reportAssignmentType]
        return referral is not None

    def use(self, user: "UserType", referral_code: str) -> None:
        """Uses referral code. Does NOT modify the referred user directly, please handle that yourself

        :param user: the user who got referred
        :type user: UserType
        :param referral_code: the referral code
        :type referral_code: str
        :raises ValueError: if referral code isnt valid
        """

        referral_code = referral_code.lower()
        logger.info(f"Using referral {referral_code}")
        lookup_request_code: str = self.users.encryption.sha256(referral_code)

        referral: ReferralType | None = self.find_item({"_id": lookup_request_code})  # pyright: ignore[reportAssignmentType]

        if referral is None:
            logger.warning("Referral does not exist!")
            msg = "Referral does not exist!"
            raise ValueError(msg)

        logger.info(f"Updating user {referral['owner']} max domains")
        self.users.table.update_one(
            {"_id": referral["owner"]},
            {"$inc": {"permissions.max-domains": 1, "referred-count": 1}},
        )

        self.modify_document(
            filter={"_id": referral["_id"]},
            operation="$push",
            key="users",
            value=user["_id"],
        )

    def get_users(self, referral_code: str) -> list["UserType"]:
        referral_code = referral_code.lower()
        referrals: list[UserType] = self.find_items({"referred-by": referral_code})  # pyright: ignore[reportAssignmentType]

        return referrals
