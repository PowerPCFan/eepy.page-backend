import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, NotRequired, Required, TypedDict, get_args

import httpx
from pymongo import MongoClient

from database.exceptions import (
    EmailException,
    InviteException,
    ReferralError,
    UsernameException,
    UserNotExistError,
)
from database.table import Table
from database.tables.referrals import Referrals
from dns_.types import AVAILABLE_TLDS
from mail.email import Email
from security.encryption import Encryption
from security.session import NewSessionType, OldSessionType

if TYPE_CHECKING:
    from database.tables.domains import DomainFormat
    from database.tables.sessions import Sessions as SessionTable
    from security.api import ApiType


logger: logging.Logger = logging.getLogger("eepy.page")


class CountryType(TypedDict):
    ip: str
    hostname: NotRequired[str]
    city: str
    region: str
    country: str  # 2 char country code (ex. FI)
    loc: str  # latitude,longtitude
    org: str
    postal: str  # Zip code
    timezone: str  # TZ format (ex. Europe/Helsinki)
    country_name: str
    isEU: bool
    country_flag_url: str
    country_flag: dict  # contains keys "emoji", and "unicode", which you can probably guess what it does
    country_currency: dict  # contains keys "code", (ex. EUR), and symbol (ex. €)
    continent: dict  # contains keys "code", (ex. EU), and name, (ex. Europe)
    latitude: str
    longitude: str


class InviteType(TypedDict):
    used: bool
    used_by: NotRequired[str]
    used_at: NotRequired[int]  # epoch timestamp


SignupType = Literal["email", "google"]

class MFA(TypedDict):
    verified: bool
    key: str
    recovery: list[str]

type EncryptedString = str

UserPageType = TypedDict(
    "UserPageType",
    {
        "username": str,
        "email": str,
        "lang": str,
        "country": CountryType | dict,
        "created": int,
        "verified": bool,
        "permissions": dict[str, Any],
        "beta-enroll": bool,
        "sessions": list[NewSessionType | OldSessionType] | list[dict],
        "invites": dict[str, InviteType],
        "mfa_enabled": bool,
        "google-connected": bool,
        "referral-code": str | None,
        "referred-people": int | None,
        "owned-tlds": list[str],
    },
)

UserType = TypedDict(
    "UserType",
    {
        "_id": str,
        "email": str,
        # Password is none if registered with google. Argon2 hash if registered with email
        "password": str | None,
        "display-name": str,
        "username": NotRequired[str],
        "lang": str,
        "country": CountryType | dict,
        "email-hash": NotRequired[str],
        "accessed-from": NotRequired[list[str]],
        "created": int,  # Epoch timestamp
        "last-login": int,  # Epoch timestamp
        "permissions": dict,
        "verified": bool,
        "registered-with": NotRequired[SignupType],
        "has-linked-google": NotRequired[bool],
        "domains": Required[dict[str, "DomainFormat"]],
        "feature-flags": NotRequired[dict[str, bool]],
        "api-keys": NotRequired[dict[str, "ApiType"]],
        "credits": NotRequired[int],
        "beta-enroll": NotRequired[bool],
        "beta-updated": NotRequired[int],
        "invites": NotRequired[dict[str, InviteType]],
        "invite-code": NotRequired[str],
        "totp": NotRequired[MFA],
        "banned": NotRequired[Literal[True]],
        "ban-reasons": NotRequired[list[str]],
        "referral-code": NotRequired[str],
        "referred-by": NotRequired[str],
        "referred-count": NotRequired[int],
        "owned-tlds": list[str],
    },
)


class Users(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "eepy.page")
        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY") or "none")
        self.referrals: Referrals = Referrals(mongo_client, self)

    def find_user(self, filter: dict, find_banned: bool = False) -> UserType | None:  # noqa: A002
        data: UserType = self.find_item(filter)  # type: ignore[return-value,assignment]

        if data:
            data = self.perform_migrations(data)
            if data.get("banned") and not find_banned:
                return None

        return data

    def find_users(self, filter: dict) -> list[UserType] | None:  # noqa: A002
        return self.find_items(filter)  # type: ignore[return-value]

    def send_discord_analytic_webhook(
        self,
        country: str,
        site_variant: Literal["canary.eepy.page", "www.eepy.page"] | str,  # noqa: PYI051
        hashed_username: str,
    ) -> None:
        start = time.time()
        with httpx.Client() as client:
            client.post(
                os.getenv("DC_WEBHOOK", ""),
                data=json.dumps(
                    {
                        "content": None,
                        "embeds": [
                            {
                                "title": "New user signup",
                                "description": f":flag_{country.lower()}: **{hashed_username}** just signed up on {site_variant} from {country}! :flag_{country.lower()}:",  # noqa: E501
                                "color": 31743,
                                "timestamp": datetime.now(UTC)
                                .isoformat(timespec="milliseconds")
                                .replace("+00:00", "Z"),
                            },
                        ],
                        "attachments": [],
                    },
                ), # pyright: ignore[reportArgumentType]
                headers={"Content-Type": "application/json"},
            )
        logger.debug(time.time() - start)

    def create_user(  # noqa: PLR0913
        self,
        username: str,
        password: str | None,
        email: str,
        language: str,
        country,  # noqa: ANN001
        time_signed_up,  # noqa: ANN001
        email_instance: Email,
        target_url: str,  # target_url should only be the hostname (e.g canary.eepy.page, www.eepy.page)
        dont_send_email: bool = False,
        signup_method: SignupType = "email",
        refer_code: str | None = None,
        skip_verification: bool = False,
    ) -> str:
        logger.info(f"Creating user with username {username}")
        original_username: str = username

        hashed_username: str = Encryption.sha256(username)
        lowercase_hashed_username = Encryption.sha256(username.lower())

        if email_instance.is_taken(email):
            logger.warning("Email is already taken")
            msg = "Email is already in use!"
            raise EmailException(msg)

        if (
            self.find_item(
                {
                    "$or": [
                        {"_id": hashed_username},
                        {"username": lowercase_hashed_username},
                    ],
                },
            )
            is not None
        ):
            msg_0 = "Username already taken!"
            raise UsernameException(msg_0)

        account_data: UserType = {
            "_id": hashed_username,
            "email": self.encryption.encrypt(email),
            "password": (
                None
                if password is None
                else self.encryption.create_password(password)
            ),
            "display-name": self.encryption.encrypt(original_username),
            "username": lowercase_hashed_username,
            "lang": language,
            "country": country,
            "email-hash": Encryption.sha256(email + "supahcool"),
            "accessed-from": [],
            "created": time_signed_up,
            "last-login": round(time.time()),
            "permissions": {
                "max-domains": 3,
                "max-subdomains": 5,
                "invite": False,
            },
            "feature-flags": {},
            "verified": bool(skip_verification),
            "domains": {},
            "api-keys": {},
            "registered-with": signup_method,
            "has-linked-google": signup_method == "google",
            "credits": 200,
            "owned-tlds": ["eepy.page"],
        }

        if refer_code:
            if self.referrals.check(refer_code):
                logger.info("User was referred, adding extra domain")
                account_data["permissions"]["max-domains"] += 1
                account_data["referred-by"] = refer_code
            else:
                logger.warning("Invalid referral code!")
                msg_1 = "Invalid referral code!"
                raise ReferralError(msg_1)

        self.insert_document(account_data)
        self.create_index("username")

        if dont_send_email:
            logger.warning(
                "Don't send info activated in create_user. This is only meant for testing environments",
            )
        elif not skip_verification and not email_instance.send_verification_code(
            target_url, hashed_username, email,
        ):
            logger.info("Failed to send verification")
            msg_2 = "Email already in use!"
            raise EmailException(msg_2)

        try:
            self.send_discord_analytic_webhook(country["country"], target_url, hashed_username)
        except Exception as e:
            logger.warning(e)

        return hashed_username

    def create_invite(self, user_id: str) -> str:
        logger.info("Creating invite...")
        invite_code: str = Encryption.generate_random_string(16)
        invite_user: UserType | None = self.find_user({"_id": user_id})

        if invite_user is None:
            msg = "User does not exist!"
            raise UserNotExistError(msg)

        if len(invite_user.get("invites", {})) >= 3:  # noqa: PLR2004
            logger.info("User has surpassed their invite limit")
            msg_0 = "Invite limit exceeded"
            raise InviteException(msg_0)

        self.table.update_one(
            {"_id": user_id},
            {
                "$set": {
                    f"invites.{invite_code}": {
                        "used": False,
                        "used_by": None,
                        "used_at": None,
                        "created": round(time.time()),
                    },
                },
            },
        )

        return invite_code

    def get_invites(self, user_id: str) -> dict[str, InviteType] | dict:
        """Get user's invites.
        Returns empty dict if no invites are found
        Raises ValueError if user does not exist
        """
        user_data: UserType | None = self.find_user({"_id": user_id})

        if user_data is None:
            msg = "Invalid user!"
            raise UserNotExistError(msg)

        return user_data.get("invites", {})

    def get_user_gdpr(self, user_id: str) -> dict:
        user_data: UserType | None = self.find_user({"_id": user_id})

        if user_data is None:
            msg = "Invalid user"
            raise UserNotExistError(msg)

        return {
            "user_id": user_data["_id"],
            "location": user_data["country"],
            "creation_date": user_data["created"],
            "domains": user_data["domains"],
            "lang": user_data["lang"],
            "last_login": user_data["last-login"],
            "permissions": user_data["permissions"],
            "verified": user_data["verified"],
        }

    def get_user_profile(
        self,
        user_id: str,
        session_table: "SessionTable",
        find_banned: bool = False,
        user_type: UserType | None = None,
    ) -> UserPageType:
        logger.info(f"Getting user profile for {user_id}")
        user_data: UserType | None = user_type or self.find_user(
            {"_id": user_id}, find_banned,
        )

        if user_data is None:
            msg = "Invalid user"
            raise UserNotExistError(msg)

        # Two different filters because in the middle of migrating the session to JWTs
        session_data = session_table.find_items(
            {
                "$or": [
                    {"owner-hash": Encryption.sha256(user_id + "eepy.page")},
                    {"$and": [{"owner": user_id}, {"type": "refresh"}]},
                ],
            },
        )  # type: ignore[assignment]

        for session in session_data:
            # NOTE: If you're an admin and want to make a session last forever, this cant handle much lol
            # I tried using 3025 and `.timestamp()` just errored out
            if session.get("expire"):
                logger.debug("Found old schema session")
                session["expires"] = round(session.get("expire").timestamp())  # type: ignore[union-attr]
                del session["expire"]

            elif session.get("expires"):
                logger.debug("Found new schema session")
                session["expires"] = round(session.get("expires").timestamp())  # type: ignore[union-attr]

        return {
            "username": self.encryption.decrypt(user_data["display-name"]),
            "email": self.encryption.decrypt(user_data["email"]),
            "lang": user_data["lang"],
            "country": user_data["country"],
            "created": user_data["created"],
            "verified": user_data["verified"],
            "permissions": user_data.get("permissions", {}),
            "beta-enroll": user_data.get("beta-enroll", False),
            "google-connected": user_data.get("has-linked-google") == True,  # noqa: E712
            "sessions": session_data,  # type: ignore[typeddict-item]
            "invites": user_data.get("invites", {}),  # type: ignore[typeddict-item]
            "mfa_enabled": user_data.get("totp", {}).get("verified", False),
            "referral-code": user_data.get("referral-code"),
            "referred-people": user_data.get("referred-count"),
            "owned-tlds": user_data.get("owned-tlds", ["eepy.page"]),
        }

    def change_beta_enrollment(self, user_id: str, mode: bool = False) -> None:
        self.modify_document({"_id": user_id}, "$set", "beta-enroll", mode)
        self.modify_document(
            {"_id": user_id}, "$set", "beta-updated", round(time.time()),
        )

    def mark_deletion_pending(self, userid: str, reasons: list[str]) -> None:
        self.table.update_one(
            {"_id": userid},
            {
                "$set": {
                    "banned": True,
                    "deleted-in": datetime.now(UTC)
                    + timedelta(weeks=52),
                },
                "$push": {"ban-reasons": {"$each": reasons}},
            },
        )
        self.delete_in_time("deleted-in")

    def perform_migrations(self, user: UserType) -> UserType:
        start = time.time()
        logger.debug(f"Running migrations for user {user['_id'][:12]}...")
        domains: dict[str, DomainFormat] = {}
        fixed_domains = False

        for domain_name, domain in user["domains"].items():
            new_domain_name: str = domain_name.lower()

            if (
                not domain_name.lower()
                .replace("[dot]", ".")
                .endswith(get_args(AVAILABLE_TLDS))
            ):
                fixed_domains = True
                logger.info(
                    f"Updated domain {domain_name.lower()} to have the new syntax",
                )
                new_domain_name = new_domain_name + "[dot]eepy[dot]page"

            if not isinstance(domain["ip"], list):
                fixed_domains = True
                logger.info("Updating domain values to be a list")

                domain["ip"] = [domain["ip"]]  # type: ignore[list-item]

            domains[new_domain_name] = domain

        if len(domains) != len(user["domains"]):
            logger.warning("Domain amount does not match!")

        elif fixed_domains:
            logger.info("Found domains which were fixed")
            self.modify_document({"_id": user["_id"]}, "$set", "domains", domains)
            user["domains"] = domains

        if not user.get("email-hash"):
            logger.info("Fixing user email hash")
            user["email-hash"] = self.encryption.sha256(
                self.encryption.decrypt(user.get("email", "")) + "supahcool",
            )
            self.modify_document(
                {"_id": user["_id"]}, "$set", "email-hash", user["email-hash"],
            )

        if len(set(user.get("accessed-from", []))) != len(
            user.get("accessed-from", []),
        ):
            logger.info("Fixing invalid accessed-from property")
            self.modify_document(
                {"_id": user["_id"]},
                "$set",
                "accessed-from",
                list(set(user.get("accessed-from", []))),
            )

        if user.get("owned-tlds") is None:
            logger.info("Updated owned TLDs")
            self.modify_document(
                {"_id": user["_id"]}, "$set", "owned-tlds", ["eepy.page"],
            )

        logger.debug(f"Migrations took {time.time() - start :.5f}s")

        return user
