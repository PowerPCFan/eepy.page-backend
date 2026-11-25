import re
from typing import TypedDict

from pydantic import BaseModel, Field, field_validator


class ServeoRecord(TypedDict):
    _id: str
    user_id: str
    serveo_auth_record: str
    ssh_fingerprint: str
    subdomain: str
    hostname: str
    service: str
    local_port: int
    command: str
    created_at: int
    updated_at: int


class TunnelCreate(BaseModel):
    subdomain: str
    local_port: int = Field(ge=1, le=65535)
    ssh_fingerprint: str = Field(min_length=10, max_length=200)

    @field_validator("ssh_fingerprint", mode="before")
    @classmethod
    def extract_ssh_fingerprint(cls, value: object) -> str:
        if not isinstance(value, str):
            msg = "SSH fingerprint must be text"
            raise ValueError(msg)  # noqa: TRY004

        match = re.search(r"SHA256:[A-Za-z0-9+/]+={0,2}", value)
        if not match:
            msg_0 = "Enter an SSH SHA256 fingerprint"
            raise ValueError(msg_0)

        return match.group(0)


class TunnelUpdate(BaseModel):
    local_port: int = Field(ge=1, le=65535)
