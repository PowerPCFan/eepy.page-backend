from pydantic import BaseModel
from typing import List

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
    backup_codes: List[str]
    app_link: str


class ApiCreationBody(BaseModel):
    permissions: List[ApiPermission]
    domains: List[str]
    comment: str


class ApiGetKeys(BaseModel):
    key: str
    domains: List[str]
    perms: List[ApiPermission]
    comment: str


class ApiDeletion(BaseModel):
    hash: str


class YearWrapped(BaseModel):
    account_created: int
    domains_registered: int
    unique_ips: int
    accounts_made_after: int
    total_users: int
