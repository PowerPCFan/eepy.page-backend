from typing import Literal

from pydantic import BaseModel

from dns_.types import TYPES


class BanUser(BaseModel):
    user_id: str
    reasons: list[str]
    send_email: bool = False


class IpFind(BaseModel):
    ips: list[str]


class UserAction(BaseModel):
    user_id: str


class AdminDomainEdit(BaseModel):
    user_id: str
    domain: str
    values: list[str]
    type: TYPES
    old_type: TYPES | None = None
    mode: Literal["both", "mongo", "pdns"] = "both"


class ManualLoginTermination(BaseModel):
    user_id: str
    refresh_token: str
