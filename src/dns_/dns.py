import json
import logging
import os

import requests  # type: ignore[import-untyped]

from database.tables.domains import DomainFormat, Domains
from dns_.exceptions import DNSException
from dns_.types import TYPES, RRSet

logger: logging.Logger = logging.getLogger("eepy.page")


class ConflictingDomain(Exception):
    pass


def sanitize(content: str, type: str) -> str:
    if (type in {"CNAME", "NS"}) and not content.rstrip().endswith("."):
        content += "."

    if type == "TXT" and not content.startswith('"'):
        content = '"' + content
    if type == "TXT" and not content.endswith('"'):
        content += '"'

    return content


class DNS:
    def __init__(self, domains: Domains) -> None:
        self.table = domains
        self.key: str = os.getenv("PDNS_API_KEY") or ""
        self.domain: str = os.getenv("PDNS_DOMAIN") or ""

    def record_exists(self, domain: str, type: str) -> bool:
        """Checks PowerDNS for an existing exact rrset before creating a user record."""
        name, tld = Domains.separate_domain_into_parts(domain)
        fqdn = name + f".{tld}."

        request = requests.get(
            f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
            headers={"X-API-Key": self.key},
            timeout=10,
        )

        if not request.ok:
            logger.error(f"Failed to check existing PowerDNS records for {domain}. {request.json()}")
            if not self.key:
                logger.critical("API key not defined!")

            msg = "Failed to check existing DNS records"
            raise DNSException(msg, request.json())

        for rrset in request.json().get("rrsets", []):
            if rrset.get("name") == fqdn and rrset.get("type") == type:
                return True

        return False

    def modify_domain(  # noqa: PLR0913
        self,
        *,
        values: list[str],
        type: TYPES,
        old_type: str,
        domain: str,
        user_id: str,
        ttl: int = 240,
    ) -> bool:
        """
        Modifies a DNS record for a given domain.
        Args:
            values (List[str]): A list of record values.
            type (TYPES): The type of DNS record (e.g., A, CNAME, TXT, NS).
            domain (str): The domain name for the DNS record.
            user_id (str): The ID of the user registering the domain
        Returns:
            bool: if record was modified successfully
        Raises:
            DNSException: If the request to modify the DNS record fails.
        """

        if type != old_type:
            success = self.delete_domain(domain, old_type)
            if not success:
                msg = "DNS Modification failed"
                raise DNSException(msg, json={"success": success})

        (name, tld) = Domains.separate_domain_into_parts(domain)

        logger.debug(f"Modifying domain {name} tld {tld}")

        # PowerDNS will complain if these two are not present.

        rrset: RRSet = {
            "changetype": "REPLACE",
            "name": name + f".{tld}.",
            "ttl": ttl,
            "type": type,
            "records": [],
        }

        for content_raw in values:
            content = sanitize(content_raw, type)
            rrset["records"].append(
                {
                    "content": content,
                    "disabled": False,
                    "comment": f"Modified by Session based auth ({user_id})",
                },
            )

        request = requests.patch(
            f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps({"rrsets": [rrset]}),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
            timeout=10,
        )

        if not request.ok:
            logger.error(f"Failed to modify domain {domain}. {request.json()}")

            if not self.key:
                logger.critical("API key not defined!")

            msg = "Failed to modify domain"
            raise DNSException(msg, request.json())

        return True

    def register_domain(
        self,
        domain: str,
        content: str,
        type: str,
        user_id: str,
    ) -> bool:
        """
        Registers a new DNS record for the specified domain.
        Args:
            domain (str): The name of the DNS record. NOTE: Must use the normal DNS schema (aka a.b.eepy.page, NOT a[dot]b[dot]eepy[dot]page)
            content (str): The content of the DNS record.
            type (str): The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
            user_id (str): ID of the user creating the record
        Returns:
            str: The ID of the newly created DNS record.
        Raises:
            DNSException: If the request to register the domain fails.
            ValueError: If the ID of the newly created DNS record cannot be retrieved.
        """  # noqa: E501

        content = sanitize(content, type)

        (name, tld) = Domains.separate_domain_into_parts(domain)

        request = requests.patch(
            f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": name + f".{tld}.",
                            "type": type,
                            "ttl": 3400,
                            "changetype": "REPLACE",
                            "records": [
                                {
                                    "content": content,
                                    "disabled": False,
                                    "comment": f"Created with Session based auth ({user_id})",
                                },
                            ],
                        },
                    ],
                },
            ),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
            timeout=10,
        )

        if not request.ok:
            logger.error(f"Failed to register domain {domain}. {request.json()}")

            if not self.key:
                logger.error("API key not defined!")

            msg = "Failed to register domain"
            raise DNSException(msg, request.json())

        return True

    def register_multiple(self, domains: dict[str, DomainFormat], user_id: str) -> bool:
        """
        Registers a new DNS record for the specified domain.
        Args:
            domain (str): The name of the DNS record. NOTE: Must use the normal DNS schema (aka a.b, NOT a[dot]b)
            content (str): The content of the DNS record.
            type (str): The type of the DNS record (e.g., A, AAAA, CNAME, etc.).
            user_id (str): ID of the user creating the record
        Returns:
            str: The ID of the newly created DNS record.
        Raises:
            DNSException: If the request to register the domain fails.
            ValueError: If the ID of the newly created DNS record cannot be retrieved.
        """

        rrsets: list[RRSet] = []

        for domain, values in domains.items():
            (name, tld) = Domains.separate_domain_into_parts(domain)

            rrset: RRSet = {
                "name": name + f".{tld}.",
                "type": values["type"],
                "ttl": 3400,
                "changetype": "REPLACE",
                "records": [],
            }

            for record in values["ip"]:
                value = sanitize(record, values["type"])
                rrset["records"].append(
                    {
                        "content": value,
                        "disabled": False,
                        "comment": f"Reinstated from banned user ({user_id})",
                    },
                )

            rrsets.append(rrset)

            request = requests.patch(
                f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
                data=json.dumps({"rrsets": rrsets}),
                headers={"Content-Type": "application/json", "X-API-Key": self.key},
                timeout=10,
            )

            if not request.ok:
                logger.error(
                    f"Failed to register domains for TLD {tld}. {request.json()}",
                )

                if not self.key:
                    logger.critical("API key not defined!")

                msg = "Failed to register domain"
                raise DNSException(msg, request.json())

        return True

    def delete_domain(self, domain: str, type: str) -> bool:
        """Deletes a domain

        :param domain: the full domain (e.g. a.b.eepy.page)
        :type domain: str
        :param type: the type of the domain (e.g. A, AAAA)
        :type type: str
        :return: whether was successfull
        :rtype: bool
        """

        (name, tld) = Domains.separate_domain_into_parts(domain)

        logger.info(f"deleting record {domain}")

        request = requests.patch(
            f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
            data=json.dumps(
                {
                    "rrsets": [
                        {
                            "name": name + f".{tld}.",
                            "type": type,
                            "changetype": "DELETE",
                            "records": [{}],
                        },
                    ],
                },
            ),
            headers={"Content-Type": "application/json", "X-API-Key": self.key},
            timeout=10,
        )

        if not request.ok:
            if not self.key:
                logger.critical("DNS API key missing!")

            logger.error(f"Could not delete domain {domain}. {request.json()}")
            return False

        return True

    def delete_multiple(self, domains: dict[str, TYPES]) -> bool:
        """Deleted multiple records at once

        Args:
            domains (Dict[str, TYPES]): A set of keys {domain: type}
        """

        logger.info(f"mass deleting records {list(domains.keys())}")

        rrsets: dict[str, list[dict]] = {}

        for domain, type in domains.items():
            (name, tld) = Domains.separate_domain_into_parts(
                Domains.legacy_bracket_domain_to_dotted(domain),
            )

            if tld not in rrsets:
                rrsets[tld] = []

            rrsets[tld].append(
                {
                    "name": name + f".{tld}.",
                    "type": type,
                    "changetype": "DELETE",
                    "records": [{}],
                },
            )

        for tld, tld_rrsets in rrsets.items():
            request = requests.patch(
                f"{self.domain}/api/v1/servers/localhost/zones/{tld}.",
                data=json.dumps({"rrsets": tld_rrsets}),
                headers={"Content-Type": "application/json", "X-API-Key": self.key},
                timeout=10,
            )

            if not request.ok:
                logger.error(
                    f"Failed to delete domains for TLD {tld}. {request.json()}",
                )

                if not self.key:
                    logger.critical("API key not defined!")

                return False
        return True
