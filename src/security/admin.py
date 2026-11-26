import logging
import re
import threading
from typing import Any

from database.exceptions import FilterMatchError, UserNotExistError
from database.models import User
from database.tables.domains import DomainFormat, Domains
from database.tables.sessions import Sessions
from database.tables.users import UserPageType, Users
from dns_.dns import DNS
from dns_.types import AVAILABLE_TLDS, TYPES
from dns_.validation import Validation
from mail.email import Email
from security.risk import RISK_THRESHOLDS, UserRisk

MAX_USERNAME_REGEX_LENGTH = 64
MAX_USERNAME_REGEX_RESULTS = 50
_UNSAFE_REGEX_META = re.compile(r"\([^)]*[+*][^)]*\)[+*?{]")


class DomainDeletionError(Exception): ...


class GenericDeletionError(Exception): ...


class AccountData(UserPageType):
    id: str
    banned: bool
    ban_reasons: list[str] | None
    last_login: int
    api_key_amount: int
    accessed_from: list[str]
    risk: UserRisk | dict[str, Any]
    risk_thresholds: dict[str, int]
    disabled: bool


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
        self.dns_validation = Validation(domains, dns)
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

    def ban_user(self, reasons: list[str], user_data: User, send_email: bool = False) -> bool:
        if len(reasons) == 0:
            msg = "You need to specify atleast one ban reason"
            raise ValueError(msg)

        domains: list[tuple[str, TYPES]] = [
            (domain.name, domain.type) for domain in Domains.normalize_domains(user_data.domains)
        ]

        success = self.dns.delete_multiple(domains)
        if not success:
            logger.critical(
                "Domain mass deletion failed! Continuing with account deletion.",
            )
            msg = "Could not delete users domain"
            raise DomainDeletionError(msg)

        self.users.mark_deletion_pending(user_data.id, reasons)

        if send_email:
            user_email: str = self.users.encryption.decrypt(user_data.email)
            self.email.send_ban_email(user_email, reasons)

        return True

    def reinstate_user(self, user_id: str, send_email: bool = False) -> None:
        user_data = self.users.get_user(
            user_id,
            find_banned=True,
        )

        if not user_data:
            msg = "User not found!"
            raise UserNotExistError(msg)
        if not user_data.banned:
            msg_0 = "User is not banned!"
            raise ValueError(msg_0)

        self.users.reinstate_user(user_id)

        domains: dict[str, DomainFormat] = {
            domain.name: {"type": domain.type, "ip": domain.ip, "registered": domain.registered}
            for domain in Domains.normalize_domains(user_data.domains)
        }

        self.dns.register_multiple(domains, user_id)
        if send_email:
            self.send_nonblocking_action_email(
                self.users.encryption.decrypt(user_data.email),
                "Account reinstated",
            )

    def find_user_by_domain(self, domain: str) -> AccountData | None:
        canonical_domain = Domains.canonical_domain_name(domain)
        user_data = self.users.find_user_by_domain_name(canonical_domain, find_banned=True)

        if not user_data:
            logger.info("Failed to find user")
            return None

        return self.get_user_details_by_id(user_data.id, user_data)

    def find_by_username(self, username: str, regex: bool = False) -> AccountData | list[AccountData] | None:  # noqa: C901
        """
        ALmost the same as get_user_details_by_id, but usernames are not case sensitive.
        When regex is true, searches across decrypted usernames with regex
        """
        if not regex:
            user = self.users.find_user_by_username_hash(username)

            if not user:
                return None

            return self.get_user_details_by_id(user.id, user)

        if len(username) > MAX_USERNAME_REGEX_LENGTH:
            msg = f"Regex pattern too long (max {MAX_USERNAME_REGEX_LENGTH} characters)"
            raise ValueError(msg)
        if _UNSAFE_REGEX_META.search(username):
            msg = "Regex pattern contains nested quantifiers"
            raise ValueError(msg)

        try:
            pattern = re.compile(username, re.IGNORECASE)
        except re.error as e:
            msg = f"Invalid regex pattern: {e}"
            raise ValueError(msg) from e

        matching_users: list[AccountData] = []
        for raw_user in self.users.get_table():
            if not raw_user.display_name:
                continue

            try:
                decrypted_username = self.users.encryption.decrypt(raw_user.display_name)
            except Exception:  # noqa: S112
                continue

            if pattern.search(decrypted_username):
                user_details = self.get_user_details_by_id(raw_user.id, raw_user)
                if user_details:
                    matching_users.append(user_details)
                    if len(matching_users) >= MAX_USERNAME_REGEX_RESULTS:
                        break

        return matching_users

    def find_by_referral(self, referral_code: str) -> AccountData | None:
        referral = self.users.referrals.get_by_id(
            self.users.encryption.sha256(referral_code),
        )

        if referral is None:
            return None

        return self.get_user_details_by_id(referral.owner)

    def find_by_ips(self, ips: list[str]) -> list[AccountData] | None:
        users = self.users.find_users_by_ips(ips)

        if not users:
            return []

        return [details for details in (self.get_user_details_by_id(u.id, u) for u in users) if details is not None]

    def get_user_details_by_id(
        self,
        user_id: str,
        user: User | None = None,
    ) -> AccountData | None:
        user_data = user or self.users.get_user(
            user_id,
            find_banned=True,
        )

        if user_data is None:
            return None

        user_profile: UserPageType = self.users.get_user_profile(
            user_id,
            session_table=self.sessions,
            find_banned=True,
            user=user_data,
        )

        return AccountData(
            **user_profile.model_dump(),
            id=user_data.id,
            banned=user_data.banned,
            ban_reasons=list(user_data.ban_reasons or []),
            last_login=round(user_data.last_login),
            api_key_amount=len(user_data.api_keys or []),
            accessed_from=list(set(user_data.accessed_ips))[:100],
            risk=user_data.risk_dict(),
            risk_thresholds=dict(RISK_THRESHOLDS),
            disabled=user_data.is_disabled,
        )

    def change_permission(
        self,
        user_id: str,
        permission: str,
        new_value: str | bool | int,
        send_email: bool = False,
    ) -> bool:
        logger.info(f"Changing user permission {permission}->{new_value}")
        try:
            user = self.get_user_details_by_id(user_id)
            if user is None:
                return False

            if send_email:
                self.send_nonblocking_action_email(
                    user.email,
                    f"Account permission changed ({permission}: {new_value})",
                )

            return self.users.set_permission(user_id, permission, new_value)

        except FilterMatchError:
            return False

    def add_domain(self, user_id: str, tld: AVAILABLE_TLDS, send_email: bool = False) -> None:
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

        if send_email:
            self.send_nonblocking_action_email(
                user.email,
                f"New TLD added to your account. (.{tld})",
            )
        self.users.add_owned_tld(user_id, tld)

    def remove_domain(self, user_id: str, tld: AVAILABLE_TLDS, send_email: bool = False) -> None:
        """Removes a TLD

        :param user_id: id of the user
        :type user_id: str
        :param tld: the tld (without the . prefix)
        :type tld: AVAILABLE_TLDS
        """
        user = self.get_user_details_by_id(user_id)
        if user is None:
            logger.warning("Couldn't find user to add domain to")
            return

        if send_email:
            self.send_nonblocking_action_email(
                user.email,
                f"TLD .{tld} has been removed from your account",
            )
        self.users.remove_owned_tld(user_id, tld)

    def verify(self, user_id: str) -> None:
        self.users.set_verified(user_id, verified=True)
