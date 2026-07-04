from pydantic import BaseModel

from database.tables.domains import DomainFormat
from dns_.types import TYPES


class DomainType(BaseModel):
    domain: str
    values: list[str]
    type: TYPES


class DomainRetrieve(BaseModel):
    domains: dict[str, DomainFormat]
    owned_tlds: list[str]
