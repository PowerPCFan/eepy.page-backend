# ruff: noqa: EM101, TRY003

from typing import Annotated

from fastapi import Header, Request

from database.tables.sessions import Sessions
from database.tables.users import Users
from security.api import Api, ApiError
from security.session import Session, SessionError


def parse_authorization_header(header: str | None) -> str:
    if header is None:
        raise SessionError("Authorization header is missing")

    scheme, _, token = header.strip().partition(" ")
    if scheme.title() == "Bearer" and token:
        return token
    else:
        raise ApiError("Authorization header is malformed")


class Convert:
    def __init__(self) -> None: ...

    def init_vars(self, users: Users, sessions: Sessions) -> None:
        self.users = users
        self.sessions = sessions

    def create(self, authorization: Annotated[str | None, Header(alias="Authorization")] = None) -> Session:
        session_id = parse_authorization_header(authorization)
        session = Session(session_id, self.users, self.sessions)
        if not session.valid:
            raise SessionError("Invalid session")
        return session


class ConvertAPI:
    def __init__(self) -> None: ...
    def init_vars(self, users: Users) -> None:
        self.users = users

    def create(self, request: Request) -> Api:
        authorization: str | None = request.headers.get("Authorization")
        api_key: str | None = None

        if authorization is not None:
            api_key = parse_authorization_header(authorization)
        if not api_key:
            api_key = request.headers.get("X-Auth-Token")
        if not api_key:
            raise ApiError("API key not specified (`Authorization: Bearer <token>` header missing)")

        return Api(api_key, self.users)
