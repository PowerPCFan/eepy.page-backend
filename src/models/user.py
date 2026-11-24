from typing import TYPE_CHECKING, Any, Literal, NotRequired, Required, TypedDict

from email_validator import EmailNotValidError, validate_email
from pydantic import field_validator
from sqlmodel import SQLModel

if TYPE_CHECKING:
    from models.domain import DomainFormat, DomainRecord
    from security.risk import UserRisk


type ApiPermission = Literal["register", "modify", "delete", "list", "userdetails"]


class ApiType(TypedDict):
    string: str
    perms: list[ApiPermission]
    domains: list[str]
    comment: str


class CountryType(TypedDict):
    ip: str
    hostname: NotRequired[str]
    city: str
    region: str
    country: str  # 2 char country code (ex. FI)
    loc: str  # latitude,longtitude
    org: str
    postal: str  # Zip code
    timezone: str  # TZ format (ex. Europe/Helsinki)
    country_name: str
    isEU: bool
    country_flag_url: str
    country_flag: dict  # contains keys "emoji", and "unicode"
    country_currency: dict  # contains keys "code", (ex. EUR), and symbol (ex. €)
    continent: dict  # contains keys "code", (ex. EU), and name, (ex. Europe)
    latitude: str
    longitude: str


class InviteType(TypedDict):
    used: bool
    used_by: NotRequired[str | None]
    used_at: NotRequired[int | None]  # epoch timestamp
    created: NotRequired[int]


class MFA(TypedDict):
    verified: bool
    key: str
    recovery: list[str]


type EncryptedString = str


class UserPageType(TypedDict):
    username: str
    email: str
    lang: str
    country: CountryType | dict
    created: int
    verified: bool
    permissions: dict[str, Any]
    domains: list["DomainRecord"] | dict[str, "DomainFormat"]
    beta_enroll: bool
    sessions: list[dict[str, Any]]
    invites: dict[str, InviteType]
    mfa_enabled: bool
    referral_code: str | None
    referred_people: int | None
    owned_tlds: list[str]


class UserType(TypedDict):
    _id: str
    email: str
    password: str | None
    display_name: str
    username: NotRequired[str]
    lang: str
    country: CountryType | dict
    email_hash: NotRequired[str]
    normalized_email_hash: NotRequired[str]
    accessed_from: NotRequired[list[str]]
    created: int
    last_login: int
    permissions: NotRequired[dict[str, Any]]
    verified: bool
    domains: Required[list["DomainRecord"] | dict[str, "DomainFormat"]]
    tunnels: NotRequired[list[dict[str, Any]]]
    feature_flags: NotRequired[dict[str, bool]]
    api_keys: NotRequired[dict[str, ApiType]]
    credits: NotRequired[int]
    beta_enroll: NotRequired[bool]
    beta_updated: NotRequired[int]
    invites: NotRequired[dict[str, InviteType]]
    invite_code: NotRequired[str]
    totp: NotRequired[MFA | dict]
    banned: NotRequired[bool]
    ban_reasons: NotRequired[list[str]]
    unbanned: NotRequired[int]
    deleted_in: NotRequired[Any]
    referral_code: NotRequired[str]
    referred_by: NotRequired[str]
    referred_count: NotRequired[int]
    owned_tlds: list[str]
    risk: NotRequired["UserRisk"]
    migration_version: NotRequired[int]


class SignUp(SQLModel):
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


class LoginRequest(SQLModel):
    username: str
    password: str


class PasswordReset(SQLModel):
    code: str
    password: str


class MfaRecovery(SQLModel):
    username: str
    password: str


class MFACreation(SQLModel):
    backup_codes: list[str]
    app_link: str


class ApiCreationBody(SQLModel):
    permissions: list[ApiPermission]
    domains: list[str]
    comment: str


class ApiGetKeys(SQLModel):
    key: str
    domains: list[str]
    perms: list[ApiPermission]
    comment: str


class ApiDeletion(SQLModel):
    hash: str


class YearWrapped(SQLModel):
    account_created: int
    domains_registered: int
    unique_ips: int
    accounts_made_after: int
    total_users: int
