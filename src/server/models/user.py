from collections.abc import Mapping
from typing import Any, Literal, Self

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, ConfigDict, field_validator

from server.models.domain import DomainRecord

type ApiPermission = Literal["register", "modify", "delete", "list", "userdetails"]


class CountryInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip: str | None = None
    hostname: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    loc: str | None = None
    org: str | None = None
    postal: str | None = None
    timezone: str | None = None
    country_name: str | None = None
    isEU: bool | None = None  # noqa: N815
    country_flag_url: str | None = None
    country_flag: dict[str, Any] | None = None
    country_currency: dict[str, Any] | None = None
    continent: dict[str, Any] | None = None
    latitude: str | None = None
    longitude: str | None = None

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any] | Self | None) -> Self:
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, Mapping):
            return cls()
        cleaned: dict[str, Any] = {}
        for field in cls.model_fields:
            val = raw.get(field)
            cleaned[field] = None if val in (None, "", {}) else val
        return cls.model_validate(cleaned)


class ApiType(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    string: str
    perms: list[ApiPermission]
    domains: list[str]
    comment: str


class InviteType(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    used: bool
    used_by: str | None = None
    used_at: int | None = None
    created: int = 0


class UserPageType(BaseModel):
    username: str
    email: str
    lang: str
    country: CountryInfo
    created: int
    verified: bool
    permissions: dict[str, Any]
    domains: list[DomainRecord]
    beta_enroll: bool
    sessions: list[dict[str, Any]]
    invites: dict[str, InviteType]
    mfa_enabled: bool
    referral_code: str | None
    referred_people: int | None
    owned_tlds: list[str]


class SignUp(BaseModel):
    username: str
    password: str
    email: str
    language: str

    @field_validator("email")
    @classmethod
    def validate_email_address(cls, v: str) -> str:
        try:
            return validate_email(v.strip(), check_deliverability=False).normalized
        except EmailNotValidError as e:
            raise ValueError(str(e)) from e


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordReset(BaseModel):
    code: str
    password: str


class MfaRecovery(BaseModel):
    username: str
    password: str


class MFACreation(BaseModel):
    backup_codes: list[str]
    app_link: str


class ApiCreationBody(BaseModel):
    permissions: list[ApiPermission]
    domains: list[str]
    comment: str


class ApiGetKeys(BaseModel):
    key: str
    domains: list[str]
    perms: list[ApiPermission]
    comment: str


class ApiDeletion(BaseModel):
    hash: str


class YearWrapped(BaseModel):
    account_created: int
    domains_registered: int
    unique_ips: int
    accounts_made_after: int
    total_users: int
