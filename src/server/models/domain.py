from typing import TypedDict

from pydantic import BaseModel, ConfigDict

from dns_.types import TYPES


class DomainFormat(TypedDict):
    ip: list[str] | str
    registered: int | float
    type: TYPES


class DomainRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    type: TYPES
    ip: list[str]
    registered: int | float


class DomainType(BaseModel):
    domain: str
    values: list[str]
    type: TYPES
    old_type: TYPES | None = None


class DomainRetrieve(BaseModel):
    domains: list[DomainRecord]
    owned_tlds: list[str]
