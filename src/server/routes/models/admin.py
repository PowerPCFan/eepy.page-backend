from pydantic import BaseModel


class BanUser(BaseModel):
    user_id: str
    reasons: list[str]


class IpFind(BaseModel):
    ips: list[str]
