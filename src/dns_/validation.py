# ruff: noqa: PLR2004, C901, PLR0911, PLR0912

import logging
import re
import string
from typing import TYPE_CHECKING, NamedTuple, get_args

from database.exceptions import SubdomainError, UserNotExistError
from database.tables.domains import DomainFormat, Domains
from database.tables.users import UserType
from dns_.exceptions import DNSException, DomainExistsError, ReservedDomainError
from dns_.types import ALLOWED_TYPES, AVAILABLE_TLDS

if TYPE_CHECKING:
    from dns_.dns import DNS

logger: logging.Logger = logging.getLogger("eepy.page")


class UserCanRegisterResult(NamedTuple):
    success: bool
    comment: str


# TODO: possibly implement https://raw.githubusercontent.com/jedireza/reserved-subdomains/refs/heads/master/names.json
# in the future
RESERVED_ROOT_LABELS: set[str] = {
    "abuse",
    "account",
    "admin",
    "api",
    "app",
    "assets",
    "auth",
    "autoconfig",
    "autodiscover",
    "billing",
    "blog",
    "bounce",
    "noreply",
    "cache",
    "content",
    "canary",
    "cdn",
    "checkout",
    "cpanel",
    "dashboard",
    "dev",
    "development",
    "dns",
    "docs",
    "ftp",
    "fsbot",
    "help",
    "health",
    "healthcheck",
    "hostmaster",
    "koti",
    "home",
    "kofi",
    "login",
    "imap",
    "localhost",
    "signin",
    "mail",
    "monitor",
    "monitoring",
    "mta-sts",
    "mx",
    "origin",
    "pop",
    "pop3",
    "postmaster",
    "redeem",
    "register",
    "root",
    "sentry",
    "smtp",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "webmail",
    "www",
    "regexp::www[0-9]+",
    "ns",
    "regexp::ns[0-9]+",
    "_acme-challenge",
    "_dmarc",
    "_domainkey",
    "_smtp",
}


class Validation:
    def __init__(self, table: Domains, dns: "DNS") -> None:
        self.dns = dns
        self.table = table

    @staticmethod
    def is_reserved_label(label: str) -> bool:
        for reserved_label in RESERVED_ROOT_LABELS:
            if reserved_label.startswith("regexp::"):
                pattern = reserved_label.removeprefix("regexp::")
                if re.fullmatch(pattern, label):
                    return True
                continue

            if label == reserved_label:
                return True

        return False

    @staticmethod
    def record_name_valid(name: str, type: str) -> bool:
        always_allowed: list[str] = list(string.ascii_letters)

        always_allowed.extend(list(string.digits))
        allowed_end = always_allowed.copy()
        allowed = always_allowed.copy()
        allowed.extend([".", "-"])

        for part in name.removesuffix(".").split("."):
            if len(part) == 0:
                return False

        if type.upper() in {"TXT", "CNAME"}:
            allowed.append("_")
            always_allowed.append("_")

        if type.upper() == "CNAME":
            allowed_end.append(".")

        valid: bool = all(char in allowed for char in name)

        if not name or (type.upper() != "TXT" and (name[0] not in always_allowed or name[-1] not in allowed_end)):
            valid = False
        return valid

    @staticmethod
    def record_value_valid(values: list[str], type: str) -> bool:
        if type.upper() == "TXT":
            return True

        all_valid: bool = True

        if len(set(values)) != len(values):
            logger.info("Found duplicate values in check, not valid")
            all_valid = False

        for value in values:
            if type.upper() in {"CNAME", "NS"}:
                if not Validation.record_name_valid(value, type):
                    all_valid = False

            elif type.upper() == "A":
                allowed: list[str] = list(string.digits)
                allowed.append(".")

                basic = all(char in allowed for char in value) and value.count(".") == 3
                if not basic:
                    all_valid = False

                for part in value.split("."):
                    if len(part) > 3:
                        all_valid = False

                    try:
                        octet = int(part)
                        if octet > 255:
                            logger.info("Octet is too big, not valid")
                            all_valid = False
                    except ValueError:
                        logger.info(f"Not a valid octet '{part}'")
                        all_valid = False

            elif type.upper() == "AAAA":
                ipv6_pattern = re.compile(
                    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
                )
                return re.match(string=value, pattern=ipv6_pattern) is not None
            else:  # If type is not in checks
                logger.error(f"Type {type} is not valid!")
                all_valid = False

        return all_valid

    @staticmethod
    def is_reserved_domain(name: str) -> bool:
        canonical_name = Domains.canonical_domain_name(name)
        for tld in get_args(AVAILABLE_TLDS):
            if canonical_name == tld:
                return True
            if not canonical_name.endswith(f".{tld}"):
                continue

            labels = [label for label in (canonical_name[: -(len(tld) + 1)]).split(".") if label]
            return len(labels) == 1 and Validation.is_reserved_label(labels[0])
        return False

    @staticmethod
    def find_required_domain(full_domain: str) -> str | None:
        """Finds the highest level of the domain. E.g a.b.eepy.page -> b.eepy.page
        Can be used to detect if domain is a subdomain using `is_subdomain = find_required_domain(...) != None`

        :param full_domain: The full domain name, including the TLD
        :type full_domain: str
        :return: If is subdomain the highest level with the TLD at the end, else None
        :rtype: str | None
        """
        domain, tld = Domains.separate_domain_into_parts(full_domain)

        domain = Domains.canonical_domain_name(domain)
        logger.info(f"Checking if {domain} is subdomain")

        domain_parts: list[str] = Domains.canonical_domain_name(domain).split(".")
        logger.info(domain_parts)
        is_subdomain: bool = len(domain_parts) > 1

        required_domain: str = domain_parts[-1] + "." + Domains.canonical_domain_name(tld)

        return required_domain if is_subdomain else None

    def is_free(
        self,
        name: str,
        type: str,
        domains: dict[str, DomainFormat],
        *,
        user_is_admin: bool = False,
        raise_exceptions: bool = True,
    ) -> bool:
        """
        Checks if a given domain name is free for registration.
        Args:
            name (str): The domain to check.
            type (str): The type of DNS record.
            domains (dict[str, DomainFormat]): A dictionary of domains owned by the user.
            raise_exceptions (bool, optional): Whether to raise exceptions on validation errors. Defaults to True.
        Returns:
            bool: True if the domain name is free, False otherwise.
        Raises:
            ValueError: If the record name is invalid and raise_exceptions is True.
            DNSException: If the DNS record type is invalid and raise_exceptions is True.
            SubdomainError: If the user doesn't own the required domain and raise_exceptions is True.
        """

        name = name.removesuffix(".")
        canonical_domain: str = Domains.canonical_domain_name(name)

        if not canonical_domain.endswith(
            tuple(f".{tld}" for tld in get_args(AVAILABLE_TLDS)),
        ):
            if raise_exceptions:
                msg = f"Invalid record name '{name}' (does not include TLD)"
                raise ValueError(msg)
            return False

        if not Validation.record_name_valid(name, type):
            logger.info(f"{name} Name is not valid")
            if raise_exceptions:
                msg = f"Invalid record name '{name}'"
                raise ValueError(msg)
            return False

        if Validation.is_reserved_domain(name) and not user_is_admin:
            logger.info(f"{name} is reserved")
            if raise_exceptions:
                msg = f"Domain '{name}' is reserved"
                raise ReservedDomainError(msg)
            return False

        if type.upper() not in ALLOWED_TYPES:
            logger.info(f"{type} is not a valid type")

            if raise_exceptions:
                msg = f"Invalid type '{type}'"
                raise DNSException(msg, type_=type)
            return False

        if canonical_domain in Domains.domain_map(domains):
            logger.info(f"User already owns domain {canonical_domain}")
            return False

        domain_label, _tld = Domains.separate_domain_into_parts(name)
        canonical_domain_label = Domains.canonical_domain_name(domain_label)

        required_domain: str | None = Validation.find_required_domain(name)

        if required_domain and required_domain not in Domains.domain_map(domains):
            logger.warning(f"User does not own {required_domain}")
            if raise_exceptions:
                msg = f"User doesn't own '{required_domain}'"
                raise SubdomainError(
                    msg,
                    required_domain,
                )
            return False

        if (
            len(
                self.table.find_item(
                    {
                        "$or": [
                            {"domains.name": canonical_domain},
                            {f"domains.{canonical_domain.replace('.', '[dot]')}": {"$exists": True}},
                            {f"domains.{canonical_domain_label.replace('.', '[dot]')}": {"$exists": True}},
                        ],
                    },
                )
                or [],
            )
            != 0
        ):
            logger.warning(f"Domain {canonical_domain} already exists in database")

            if raise_exceptions:
                msg = "Domain is already registered"
                raise DomainExistsError(msg)
            return False

        logger.info("Domain not found in database.")

        return True

    def user_owns_domain(
        self,
        user_id: str,
        domain: str,
        user: UserType | None = None,
    ) -> bool:
        """Returns whether user has a specfic domain owned. Can bee passed a user_id or user. If user_id is passed, a database lookup occurs.

        :param user_id: the ID of the user to check
        :type user_id: str
        :param domain: the full domain name
        :type domain: str
        :param user: the user object, if provided, no database lookup occusr, defaults to None
        :type user: UserType | None, optional
        :raises UserNotExistError: if the user does not exist
        :return: whether user owns domain
        :rtype: bool
        """  # noqa: E501
        if not user:
            user_data: UserType | None = self.table.find_user({"_id": user_id})
        else:
            user_data = user
        if user_data is None:
            msg = "User does not exist!"
            raise UserNotExistError(msg)

        return Domains.get_domain(user_data["domains"], domain) is not None

    @staticmethod
    def can_user_register(domain: str, user: UserType) -> UserCanRegisterResult:
        """Checks whether users domain limit allows them to register a domain

        :param domain: a beautified domain, eg a.b.eepy.page
        :type domain: str
        :param user: the user who is registering
        :type user: UserType
        :return: whether the user can register
        :rtype: UserCanRegisterResult
        """
        subdomain_amount: int = 0
        is_subdomain = Validation.find_required_domain(domain) is not None

        user_domain_amount = 0
        subdomain_amount = 0

        for user_domain in Domains.domain_names(user["domains"]):
            if Validation.find_required_domain(user_domain):
                subdomain_amount += 1
            else:
                user_domain_amount += 1

        logger.info(
            f"User has {subdomain_amount} subdomains and {user_domain_amount} domains",
        )

        user_max_domains = user.get("permissions", {}).get("max-domains", 3)
        user_max_subdomains = user.get("permissions", {}).get("max-subdomains", 5)

        if not is_subdomain and user_domain_amount >= user_max_domains:
            return UserCanRegisterResult(success=False, comment="Domain limit exceeded")

        if is_subdomain and subdomain_amount >= user_max_subdomains:
            return UserCanRegisterResult(success=False, comment="Subdomain limit exceeded")

        return UserCanRegisterResult(success=True, comment="")
