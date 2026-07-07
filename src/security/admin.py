import logging
import threading
import time
from typing import TYPE_CHECKING

from database.exceptions import FilterMatchError, UserNotExistError
from database.tables.domains import DomainRecord, Domains
from database.tables.sessions import Sessions
from database.tables.users import UserPageType, Users, UserType
from dns_.dns import DNS
from dns_.types import AVAILABLE_TLDS, TYPES
from mail.email import Email
from security.encryption import Encryption

if TYPE_CHECKING:
    from database.tables.referrals import ReferralType


class DomainDeletionError(Exception): ...


class GenericDeletionError(Exception): ...


class AccountData(UserPageType):
    domains: list[DomainRecord]
    id: str
    banned: bool
    ban_reasons: list[str] | list[list[str]] | None
    last_login: int
    api_key_amount: int
    accessed_from: list[str]


logger: logging.Logger = logging.getLogger("eepy.page")


class Admin:
    def __init__(
        self,
        users_table: Users,
        sessions_table: Sessions,
        domains: Domains,
        dns: DNS,
        mail: Email,
    ) -> None:
        self.users = users_table
        self.domains = domains
        self.dns = dns
        self.email = mail
        self.sessions = sessions_table

    def send_nonblocking_action_email(
        self,
        email: str,
        actions: str,
    ) -> threading.Thread:
        thread = threading.Thread(
            target=self.email.send_admin_email,
            args=(email, actions),
        )
        thread.start()
        return thread

    def ban_user(self, reasons: list[str], user_data: UserType) -> bool:
        if len(reasons) == 0:
            msg = "You need to specify atleast one ban reason"
            raise ValueError(msg)

        domains: dict[str, TYPES] = {
            domain["name"]: domain["type"] for domain in Domains.normalize_domains(user_data["domains"])
        }

        success = self.dns.delete_multiple(domains)
        if not success:
            logger.critical(
                "Domain mass deletion failed! Continuing with account deletion.",
            )
            msg = "Could not delete users domain"
            raise DomainDeletionError(msg)

        self.users.mark_deletion_pending(user_data["_id"], reasons)

        user_email: str = self.users.encryption.decrypt(user_data["email"])
        self.email.send_ban_email(user_email, reasons)

        return True

    def reinstate_user(self, user_id: str) -> None:
        user_data: UserType | None = self.users.find_user(
            {"_id": user_id},
            find_banned=True,
        )

        if not user_data:
            msg = "User not found!"
            raise UserNotExistError(msg)
        if not user_data.get("banned", False):
            msg_0 = "User is not banned!"
            raise ValueError(msg_0)

        self.users.table.update_one(
            {"_id": user_id},
            {
                "$set": {"banned": False, "unbanned": round(time.time())},
                "$unset": {"deleted-in": 1},
            },
        )

        domains = {domain["name"]: domain for domain in Domains.normalize_domains(user_data["domains"])}

        self.dns.register_multiple(domains, user_id)
        self.send_nonblocking_action_email(
            self.users.encryption.decrypt(user_data["email"]),
            "Account reinstated",
        )

    def find_user_by_domain(self, domain: str) -> AccountData | None:
        canonical_domain = Domains.canonical_domain_name(domain)
        user_data = self.users.find_user(
            {
                "$or": [
                    {"domains.name": canonical_domain},
                    {f"domains.{canonical_domain.replace('.', '[dot]')}": {"$exists": True}},
                ],
            },
            find_banned=True,
        )

        if not user_data:
            logger.info("Failed to find user")
            return None

        return self.get_user_details_by_id(user_data["_id"])

    def find_by_username(self, username: str) -> AccountData | None:
        """
        ALmost the same as get_user_details_by_id, but usernames are not case sensitive
        """

        user: UserType | None = self.users.find_user(
            {
                "$or": [
                    {"_id": Encryption.sha256(username)},
                    {"username": Encryption.sha256(username.lower())},
                ],
            },
        )

        if not user:
            return None

        return self.get_user_details_by_id(user["_id"])

    def find_by_referral(self, referral_code: str) -> AccountData | None:
        referral: ReferralType | None = self.users.referrals.find_item(
            {"_id": self.users.encryption.sha256(referral_code)},
        )  # type: ignore[assignment]

        if referral is None:
            return None

        return self.get_user_details_by_id(referral["owner"])

    def find_by_ips(self, ips: list[str]) -> list[AccountData] | None:
        users = self.users.find_users({"accessed-from": {"$in": ips}})

        if users is None:
            return None

        return [
            user
            for user in [self.get_user_details_by_id(user["_id"], user) for user in users if user is not None]
            if user is not None
        ]

    def get_user_details_by_id(
        self,
        user_id: str,
        user_type: UserType | None = None,
    ) -> AccountData | None:
        user_profile: UserPageType | None = self.users.get_user_profile(
            user_id,
            session_table=self.sessions,
            find_banned=True,
            user_type=user_type,
        )

        if not user_profile:
            logger.info("User profile did not yield results")
            return None

        user_data: UserType | None = user_type or self.users.find_user(
            filter={"_id": user_id},
            find_banned=True,
        )

        if user_data is None:
            msg = "Could not get user from db"
            raise ValueError(msg)

        account_data: AccountData = user_profile  # type: ignore[assignment]
        account_data["domains"] = user_data["domains"]
        account_data["id"] = user_data["_id"]
        account_data["banned"] = user_data.get("banned", False)
        account_data["ban_reasons"] = user_data.get("ban-reasons")
        account_data["last_login"] = round(user_data.get("last-login", 0))
        account_data["created"] = round(user_data.get("created", 0))
        account_data["api_key_amount"] = len(user_data.get("api-keys", []))
        account_data["accessed_from"] = list(set(user_data.get("accessed-from", [])))[:100]

        return account_data

    def change_permission(
        self,
        user_id: str,
        permission: str,
        new_value: str | bool | int,
    ) -> bool:
        logger.info(f"Changing user permission {permission}->{new_value}")
        try:
            user = self.get_user_details_by_id(user_id)
            if user is None:
                return False

            self.send_nonblocking_action_email(
                user["email"],
                f"Account permission changed ({permission}: {new_value})",
            )

            self.users.modify_document(
                filter={"_id": user_id},
                operation="$set",
                key=f"permissions.{permission}",
                value=new_value,
            )

            return True

        except FilterMatchError:
            return False

    def add_domain(self, user_id: str, tld: AVAILABLE_TLDS) -> None:
        """Adds domain to TLDs

        :param user_id: id of the user
        :type user_id: str
        :param tld: the tld (without the . prefix)
        :type tld: AVAILABLE_TLDS
        """
        user = self.get_user_details_by_id(user_id)
        if user is None:
            logger.warning("Couldn't find user to add domain to")
            return

        self.send_nonblocking_action_email(
            user["email"],
            f"New TLD added to your account. (.{tld})",
        )
        self.users.modify_document(
            filter={"_id": user_id},
            operation="$push",
            key="owned-tlds",
            value=tld,
        )

    def remove_domain(self, user_id: str, tld: AVAILABLE_TLDS) -> None:
        """Removes a TLD

        :param user_id: id of the user
        :type user_id: str
        :param tld: the tld (without . prefix)
        :type tld: AVAILABLE_TLDS
        """
        user = self.get_user_details_by_id(user_id)
        if user is None:
            logger.warning("Couldn't find user to add domain to")
            return

        self.send_nonblocking_action_email(
            user["email"],
            f"TLD .{tld} has been removed from your account",
        )
        self.users.modify_document(
            filter={"_id": user_id},
            operation="$pull",
            key="owned-tlds",
            value=tld,
        )

    def verify(self, user_id: str) -> None:
        self.users.modify_document(
            filter={"_id": user_id},
            operation="$set",
            key="verified",
            value=True,
        )
