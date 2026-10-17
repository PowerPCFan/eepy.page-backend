from disposable_email_domains import blocklist
from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, field_validator

from security.api import ApiPermission


class SignUp(BaseModel):
    username: str
    password: str
    email: str
    language: str

    @field_validator("email")
    @classmethod
    def validate_email_address(cls, v: str) -> str:
        try:
            normalized = validate_email(v.strip(), check_deliverability=False).normalized
        except EmailNotValidError as e:
            raise ValueError(str(e)) from e

        domain = normalized.split("@")[-1].lower()
        if domain in blocklist:
            msg = "Disposable email addresses are not allowed"
            raise ValueError(msg)

        return normalized


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
