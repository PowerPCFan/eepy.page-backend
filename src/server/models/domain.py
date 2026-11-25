from typing import NotRequired, TypedDict

from pydantic import BaseModel

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


class DomainType(BaseModel):
    domain: str
    values: list[str]
    type: TYPES
    old_type: TYPES | None = None


class DomainRetrieve(BaseModel):
    domains: list[DomainRecord]
    owned_tlds: list[str]
