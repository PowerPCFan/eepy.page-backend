import logging
from collections.abc import Mapping, Sequence
from itertools import starmap
from typing import TYPE_CHECKING, get_args

from sqlalchemy import or_, select
from sqlalchemy.orm.attributes import flag_modified

from database.exceptions import UserNotExistError
from database.models import Domain, User
from database.table import Table
from dns_.types import AVAILABLE_TLDS, TYPES, get_record_type
from server.models.domain import DomainFormat, DomainRecord

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

type DomainInput = Sequence[Domain | DomainRecord] | Mapping[str, DomainFormat] | None

__all__ = ["DomainFormat", "DomainInput", "DomainRecord", "Domains"]


class Domains(Table[Domain]):
    """Modifies domains in database.
    Please make sure to validate the domain BEFORE you use any functions here!
    """

    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, Domain)

    @staticmethod
    def canonical_domain_name(domain: str) -> str:
        return domain.removesuffix(".").lower()

    @staticmethod
    def canonical_full_domain_name(domain: str) -> str:
        canonical_domain = Domains.canonical_domain_name(domain)
        for available_tld in get_args(AVAILABLE_TLDS):
            if canonical_domain == available_tld or canonical_domain.endswith(f".{available_tld}"):
                return canonical_domain

        return f"{canonical_domain}.eepy.page"

    @staticmethod
    def record_key(domain: str, type_: str) -> str:
        return f"{Domains.canonical_full_domain_name(domain)}::{type_.upper()}"

    @staticmethod
    def separate_domain_into_parts(domain: str) -> tuple[str, str]:
        tld: str = "eepy.page"
        clean_domain = domain.removesuffix(".").lower()

        for available_tld in get_args(AVAILABLE_TLDS):
            if clean_domain == available_tld or clean_domain.endswith(f".{available_tld}"):
                tld = available_tld
                break

        return (clean_domain.rsplit(tld, 1)[0].rstrip("."), tld)

    @staticmethod
    def normalize_domain_record(domain: str, domain_data: DomainFormat) -> DomainRecord:
        ip_val = domain_data["ip"]
        return DomainRecord(
            name=Domains.canonical_full_domain_name(domain),
            type=get_record_type(domain_data["type"].upper()),
            ip=list(ip_val) if isinstance(ip_val, list) else [ip_val],
            registered=domain_data["registered"],
        )

    @staticmethod
    def normalize_domains(domains: DomainInput) -> list[DomainRecord]:
        if not domains:
            return []

        if isinstance(domains, Mapping):
            return list(starmap(Domains.normalize_domain_record, domains.items()))

        normalized_domains: list[DomainRecord] = []
        for domain in domains:
            if not domain.name:
                continue
            normalized_domains.append(
                DomainRecord(
                    name=Domains.canonical_full_domain_name(domain.name),
                    type=get_record_type(domain.type.upper()),
                    ip=list(domain.ip) if isinstance(domain.ip, list) else [str(domain.ip)],
                    registered=domain.registered,
                ),
            )
        return normalized_domains

    @staticmethod
    def domain_map(domains: DomainInput) -> dict[str, DomainRecord]:
        return {Domains.record_key(domain.name, domain.type): domain for domain in Domains.normalize_domains(domains)}

    @staticmethod
    def get_domain(
        domains: DomainInput,
        domain: str,
        type: str | None = None,
    ) -> DomainRecord | None:
        canonical_domain = Domains.canonical_full_domain_name(domain)
        normalized_domains = Domains.normalize_domains(domains)

        if type is not None:
            type_upper = type.upper()
            for record in normalized_domains:
                if record.name == canonical_domain and record.type == type_upper:
                    return record
            return None

        matches = [record for record in normalized_domains if record.name == canonical_domain]
        if len(matches) == 1:
            return matches[0]
        return None

    @staticmethod
    def domain_names(domains: DomainInput) -> list[str]:
        names: list[str] = []
        for domain in Domains.normalize_domains(domains):
            if domain.name not in names:
                names.append(domain.name)
        return names

    @staticmethod
    def has_domain(
        domains: DomainInput,
        domain: str,
        type: str | None = None,
    ) -> bool:
        canonical_domain = Domains.canonical_full_domain_name(domain)
        type_upper = type.upper() if type is not None else None
        return any(
            record.name == canonical_domain and (type_upper is None or record.type == type_upper)
            for record in Domains.normalize_domains(domains)
        )

    @staticmethod
    def get_child_subdomains(
        domains: DomainInput,
        parent_domain: str,
    ) -> list[str]:
        parent_canonical = Domains.canonical_full_domain_name(parent_domain)
        subdomains: list[str] = []
        for record in Domains.normalize_domains(domains):
            name = record.name
            if name != parent_canonical and name.endswith(f".{parent_canonical}") and name not in subdomains:
                subdomains.append(name)
        return subdomains

    @staticmethod
    def will_domain_be_removed(
        domains: DomainInput,
        domain: str,
        type: str | None = None,
    ) -> bool:
        canonical_domain = Domains.canonical_full_domain_name(domain)
        matching = [record for record in Domains.normalize_domains(domains) if record.name == canonical_domain]
        if not matching:
            return False
        if type is None:
            return len(matching) == 1
        remaining = [record for record in matching if record.type != type.upper()]
        return len(remaining) == 0

    def get_user(self, user_id: str, find_banned: bool = False) -> User | None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None or (user.banned and not find_banned):
                return None
            return user

    def get_all_domain_records(self, exclude_user_id: str | None = None) -> list[Domain]:
        with self.session() as session:
            stmt = select(Domain)
            if exclude_user_id is not None:
                stmt = stmt.where(Domain.user_id != exclude_user_id)
            return list(session.scalars(stmt).all())

    def find_overlapping_domain(self, domain: str, exclude_user_id: str | None = None) -> str | None:
        canonical_full = Domains.canonical_full_domain_name(domain)
        labels = canonical_full.split(".")
        candidates = [".".join(labels[i:]) for i in range(max(1, len(labels) - 2))]
        with self.session() as session:
            stmt = select(Domain.name).where(
                or_(
                    Domain.name.in_(candidates),
                    Domain.name.endswith(f".{canonical_full}", autoescape=True),
                ),
            )
            if exclude_user_id is not None:
                stmt = stmt.where(Domain.user_id != exclude_user_id)
            return session.scalars(stmt).first()

    def add_domain(
        self,
        target_user: str,
        domain: str,
        domain_data: DomainFormat,
    ) -> None:
        domain_record = Domains.normalize_domain_record(domain, domain_data)
        with self.session() as session:
            user = session.get(User, target_user)
            if user is None:
                return
            stmt = select(Domain).where(
                Domain.user_id == target_user,
                Domain.name == domain_record.name,
                Domain.type == domain_record.type,
            )
            existing = session.scalars(stmt).first()
            if existing is not None:
                existing.ip = list(domain_record.ip)
                existing.registered = int(domain_record.registered)
                flag_modified(existing, "ip")
                session.add(existing)
            else:
                session.add(
                    Domain(
                        user_id=target_user,
                        name=domain_record.name,
                        type=domain_record.type,
                        ip=list(domain_record.ip),
                        registered=int(domain_record.registered),
                    ),
                )

    def get_domains(self, target_user: str) -> list[Domain]:
        with self.session() as session:
            user = session.get(User, target_user)
            if user is None or user.banned:
                msg = "User does not exist"
                raise UserNotExistError(msg)
            return list(user.domains or [])

    def modify_domain(  # noqa: PLR0913
        self,
        target_user: str,
        domain: str,
        value: list[str] | str | None = None,
        type: TYPES | None = None,
        old_type: TYPES | None = None,
        *,
        allow_banned: bool = False,
    ) -> bool:
        canonical_domain: str = Domains.canonical_full_domain_name(domain)
        logger.info(f"Modifying domain {canonical_domain}...")

        with self.session() as session:
            user = session.get(User, target_user)
            if user is None or (user.banned and not allow_banned):
                msg = "Failed to find user"
                raise ValueError(msg)

            target_type = (old_type or type or "").upper() if (old_type or type) else None
            stmt = select(Domain).where(
                Domain.user_id == target_user,
                Domain.name == canonical_domain,
            )
            matches = list(session.scalars(stmt).all())

            target_row: Domain | None = None
            if old_type is not None:
                old_upper = old_type.upper()
                target_row = next((m for m in matches if m.type == old_upper), None)
            elif len(matches) == 1:
                if type is None or matches[0].type == type.upper():
                    target_row = matches[0]
            elif target_type:
                target_row = next((m for m in matches if m.type == target_type), None)

            if target_row is None:
                msg = "Domain not found"
                raise ValueError(msg)

            new_type_upper = get_record_type((type or target_row.type).upper())
            if new_type_upper != target_row.type:
                conflict = next((m for m in matches if m.type == new_type_upper), None)
                if conflict is not None:
                    msg = "Domain already exists"
                    raise ValueError(msg)

            if value is not None:
                target_row.ip = list(value) if isinstance(value, list) else [value]
                flag_modified(target_row, "ip")
            target_row.type = new_type_upper
            session.add(target_row)
            return True

    def delete_domain(
        self,
        target_user: str,
        domain: str,
        type: str | None = None,
        *,
        allow_banned: bool = False,
    ) -> bool:
        canonical_domain = Domains.canonical_full_domain_name(domain)
        logger.info(f"Deleting domain {canonical_domain}")

        with self.session() as session:
            user = session.get(User, target_user)
            if user is None or (user.banned and not allow_banned):
                return False

            stmt = select(Domain).where(
                Domain.user_id == target_user,
                Domain.name == canonical_domain,
            )
            matches = list(session.scalars(stmt).all())
            if not matches:
                return False

            target_row: Domain | None = None
            if type is not None:
                type_upper = type.upper()
                target_row = next((m for m in matches if m.type == type_upper), None)
            elif len(matches) == 1:
                target_row = matches[0]

            if target_row is None:
                return False

            session.delete(target_row)
            return True
