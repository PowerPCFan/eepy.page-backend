from pydantic import BaseModel

from security.api import ApiPermission


class SignUp(BaseModel):
    username: str
    password: str
    email: str
    language: str


class LoginRequest(BaseModel):
    username_hash: str
    password: str
    plain_username: str | None = None


class PasswordReset(BaseModel):
    code: str
    password: str


class MfaRecovery(BaseModel):
    username_hash: str
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
