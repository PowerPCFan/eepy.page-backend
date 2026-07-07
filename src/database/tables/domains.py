import logging
from itertools import starmap
from typing import NotRequired, TypedDict, get_args

from pymongo import MongoClient

from database.exceptions import UserNotExistError
from database.tables.users import Users, UserType
from dns_.types import AVAILABLE_TLDS, TYPES

logger: logging.Logger = logging.getLogger("eepy.page")


class DomainFormat(TypedDict):
    ip: list[str] | str
    registered: int | float
    type: TYPES
    id: str | None


class DomainRecord(DomainFormat):
    name: str


RepairFormat = TypedDict(
    "RepairFormat",
    {
        "fixed": int,
        "skipped": int,
        "duplicates": int,
        "broken-id": NotRequired[dict[str, DomainFormat]],
    },
)


class Domains(Users):
    """Modifies domains in database.
    Please make sure to validate the domain BEFORE you use any functions here!
    """

    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client)

    @staticmethod
    def canonical_domain_name(domain: str) -> str:
        return Domains.legacy_bracket_domain_to_dotted(domain).removesuffix(".").lower()

    @staticmethod
    def canonical_full_domain_name(domain: str) -> str:
        canonical_domain = Domains.canonical_domain_name(domain)
        if canonical_domain.endswith(get_args(AVAILABLE_TLDS)):
            return canonical_domain

        return f"{canonical_domain}.eepy.page"

    @staticmethod
    def separate_domain_into_parts(domain: str) -> tuple[str, str]:
        """Returns the name and TLD of the domain

        :param domain: the full domain (e.g a.eepy.page)
        :type domain: str
        :return: name, tld. NOTE: the name does not include a dot at the end, and the tld does not contain a dot at the beginning. Looks something like this: (a, eepy.page)
        :rtype: Tuple[str, str]
        """  # noqa: E501
        tld: str = "eepy.page"

        dotted_domain = Domains.legacy_bracket_domain_to_dotted(domain)

        for available_tld in get_args(AVAILABLE_TLDS):
            if dotted_domain.endswith(available_tld):
                tld = available_tld
                break

        return (dotted_domain.rsplit(tld, 1)[0].rstrip("."), tld)

    @staticmethod
    def legacy_bracket_domain_to_dotted(domain: str) -> str:
        return domain.replace("[dot]", ".")

    @staticmethod
    def display_domain_name(domain: str) -> str:
        return Domains.legacy_bracket_domain_to_dotted(domain)

    @staticmethod
    def normalize_domain_record(domain: str, domain_data: DomainFormat) -> DomainRecord:
        return {
            "name": Domains.canonical_full_domain_name(domain),
            "id": domain_data.get("id"),
            "type": domain_data["type"],
            "ip": domain_data["ip"] if isinstance(domain_data["ip"], list) else [domain_data["ip"]],
            "registered": domain_data["registered"],
        }

    @staticmethod
    def normalize_domains(domains: dict[str, DomainFormat] | list[DomainRecord] | None) -> list[DomainRecord]:
        if not domains:
            return []

        if isinstance(domains, list):
            normalized_domains: list[DomainRecord] = []
            for domain in domains:
                if not domain.get("name"):
                    continue
                normalized_domains.append(Domains.normalize_domain_record(domain["name"], domain))
            return normalized_domains

        return list(starmap(Domains.normalize_domain_record, domains.items()))

    @staticmethod
    def domain_map(domains: dict[str, DomainFormat] | list[DomainRecord] | None) -> dict[str, DomainRecord]:
        return {domain["name"]: domain for domain in Domains.normalize_domains(domains)}

    @staticmethod
    def get_domain(
        domains: dict[str, DomainFormat] | list[DomainRecord] | None,
        domain: str,
    ) -> DomainRecord | None:
        return Domains.domain_map(domains).get(Domains.canonical_full_domain_name(domain))

    @staticmethod
    def domain_names(domains: dict[str, DomainFormat] | list[DomainRecord] | None) -> list[str]:
        return [domain["name"] for domain in Domains.normalize_domains(domains)]

    def add_domain(
        self,
        target_user: str,
        domain: str,
        domain_data: DomainFormat,
    ) -> None:
        domain_record = Domains.normalize_domain_record(domain, domain_data)
        result = self.table.update_one(
            {"_id": target_user, "domains.name": domain_record["name"]},
            {"$set": {"domains.$": domain_record}},
        )

        if result.matched_count == 0:
            self.table.update_one({"_id": target_user}, {"$push": {"domains": domain_record}})

    def get_domains(self, target_user: str) -> list[DomainRecord]:
        user_data: UserType | None = self.find_user({"_id": target_user})
        if user_data is None:
            msg = "User does not exist"
            raise UserNotExistError(msg)

        return Domains.normalize_domains(user_data["domains"])

    def modify_domain(
        self,
        target_user: str,
        domain: str,
        value: str | None = None,
        type: TYPES | None = None,
    ) -> None:
        """Modifies domain in database

        Args:
            target_user (str): ID of target user
            domain (str): the record name with the TLD attached (e.g domain.eepy.page)
            value (str | None, optional): Updated record value. Defaults to current one.
            type (str | None, optional): Updated type value. Defaults to current one.

        Raises:
            ValueError: If user does not exist
        """
        canonical_domain: str = Domains.canonical_full_domain_name(domain)
        logger.info(f"Modifying domain {canonical_domain}...")

        user_data: UserType | None = self.find_user({"_id": target_user})
        if user_data is None:
            msg = "Failed to find user"
            raise ValueError(msg)

        domain_data = Domains.get_domain(user_data["domains"], canonical_domain)
        if domain_data is None:
            msg = "Domain not found"
            raise ValueError(msg)

        updated_domain_data: DomainRecord = {
            "name": canonical_domain,
            "ip": value or domain_data["ip"],
            "registered": domain_data["registered"],
            "type": type or domain_data["type"],
            "id": domain_data["id"],
        }

        self.table.update_one(
            {"_id": target_user, "domains.name": canonical_domain},
            {"$set": {"domains.$": updated_domain_data}},
        )

    def delete_domain(self, target_user: str, domain: str) -> bool:
        canonical_domain = Domains.canonical_full_domain_name(domain)
        logger.info(f"Deleting domain {canonical_domain}")

        return (
            self.table.update_one(
                {"_id": target_user},
                {"$pull": {"domains": {"name": canonical_domain}}},
            ).modified_count
            != 0
        )
