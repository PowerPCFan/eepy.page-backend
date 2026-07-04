from fastapi import Request

from database.tables.sessions import Sessions
from database.tables.users import Users
from security.api import Api, ApiError
from security.session import Session, SessionError


class Convert:
    def __init__(self) -> None: ...

    def init_vars(self, users: Users, sessions: Sessions) -> None:
        self.users = users
        self.sessions = sessions

    def create(self, request: Request) -> Session:
        session_id: str | None = request.headers.get("X-Auth-Token")
        if session_id is None:
            msg = "Session id is none"
            raise SessionError(msg)

        return Session(session_id, self.users, self.sessions)  # type: ignore[union-attr]


class ConvertAPI:
    def __init__(self) -> None: ...
    def init_vars(self, users: Users) -> None:
        self.users = users

    def create(self, request: Request) -> Api:
        api_key: str | None = request.headers.get("X-API-Token")
        if api_key is None:
            msg = "API Key not specified (X-API-Token header missing)"
            raise ApiError(msg)

        return Api(api_key, self.users)
