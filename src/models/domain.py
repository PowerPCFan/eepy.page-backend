from typing import NotRequired, TypedDict

from sqlmodel import SQLModel

from dns_.types import TYPES


class DomainFormat(TypedDict):
    ip: list[str] | str
    registered: int | float
    type: TYPES


class DomainRecord(DomainFormat):
    name: str


class RepairFormat(TypedDict):
    fixed: int
    skipped: int
    duplicates: int
    broken_id: NotRequired[dict[str, DomainFormat]]


class DomainType(SQLModel):
    domain: str
    values: list[str]
    type: TYPES
    old_type: TYPES | None = None


class DomainRetrieve(SQLModel):
    domains: list[DomainRecord]
    owned_tlds: list[str]
