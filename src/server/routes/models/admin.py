from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from dns_.types import TYPES
from security.admin_permissions import ADMIN_PERMISSION_NAMES


class BanUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: StrictStr
    reasons: list[StrictStr]
    send_email: StrictBool = False

    @model_validator(mode="after")
    def validate_reasons(self) -> "BanUser":
        if len(self.reasons) == 0:
            msg = "At least one ban reason is required"
            raise ValueError(msg)
        if any(reason.strip() == "" for reason in self.reasons):
            msg_0 = "Ban reasons cannot be empty"
            raise ValueError(msg_0)
        return self


class IpFind(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[StrictStr]

    @model_validator(mode="after")
    def validate_ips(self) -> "IpFind":
        if len(self.ips) == 0:
            msg = "At least one IP address is required"
            raise ValueError(msg)
        if any(ip.strip() == "" for ip in self.ips):
            msg_0 = "IP addresses cannot be empty"
            raise ValueError(msg_0)
        return self


class UserAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: StrictStr


class AdminPermissionChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: StrictStr
    permission: StrictStr
    value: bool | StrictInt | StrictStr
    send_email: StrictBool = False

    @field_validator("permission")
    def validate_permission(cls, permission: str) -> str:  # noqa: N805
        valid_permissions = {"enabled", "max-domains", "max-subdomains", *ADMIN_PERMISSION_NAMES}
        if permission not in valid_permissions:
            msg = f"Invalid permission '{permission}'"
            raise ValueError(msg)
        return permission

    @model_validator(mode="after")
    def validate_value(self) -> "AdminPermissionChange":  # noqa: C901
        permission = self.permission
        value = self.value

        if permission in {"max-domains", "max-subdomains"}:
            if isinstance(value, bool):
                msg = "Permission value must be an integer"
                raise ValueError(msg)
            if isinstance(value, str):
                if not value.isdigit():
                    msg_0 = "Permission value must be an integer"
                    raise ValueError(msg_0)
                return self.model_copy(update={"value": int(value)})
            if isinstance(value, int):
                return self
            msg_1 = "Permission value must be an integer"
            raise ValueError(msg_1)

        if permission == "enabled" or permission in ADMIN_PERMISSION_NAMES:
            if isinstance(value, bool):
                return self
            if isinstance(value, int):
                if value in {0, 1}:
                    return self.model_copy(update={"value": bool(value)})
                msg_2 = "Permission value must be a boolean"
                raise ValueError(msg_2)
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {"true", "1", "yes", "on"}:
                    return self.model_copy(update={"value": True})
                if normalized in {"false", "0", "no", "off"}:
                    return self.model_copy(update={"value": False})
                msg = "Permission value must be a boolean"
                raise ValueError(msg)
            msg_0 = "Permission value must be a boolean"
            raise ValueError(msg_0)

        msg_1 = "Unable to validate permission value"
        raise ValueError(msg_1)


class AdminDomainEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: StrictStr
    domain: StrictStr
    values: list[StrictStr]
    type: TYPES
    old_type: TYPES | None = None
    mode: Literal["both", "mongo", "pdns"] = "both"

    @model_validator(mode="after")
    def validate_values(self) -> "AdminDomainEdit":
        if len(self.values) == 0:
            msg = "At least one value is required"
            raise ValueError(msg)
        if any(value.strip() == "" for value in self.values):
            msg_0 = "Values cannot contain empty strings"
            raise ValueError(msg_0)
        return self


class ManualLoginTermination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: StrictStr
    refresh_token: StrictStr
