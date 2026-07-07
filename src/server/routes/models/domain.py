from pydantic import BaseModel

from database.tables.domains import DomainRecord
from dns_.types import TYPES


class DomainType(BaseModel):
    domain: str
    values: list[str]
    type: TYPES


class DomainRetrieve(BaseModel):
    domains: list[DomainRecord]
    owned_tlds: list[str]
