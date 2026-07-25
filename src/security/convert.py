from typing import Annotated

from fastapi import Header, Request

from database.tables.sessions import Sessions
from database.tables.users import Users
from security.api import Api, ApiError
from security.session import Session, SessionError


class Convert:
    def __init__(self) -> None: ...

    def init_vars(self, users: Users, sessions: Sessions) -> None:
        self.users = users
        self.sessions = sessions

    def create(self, session_id: Annotated[str | None, Header(alias="X-Auth-Token")] = None) -> Session:
        if session_id is None:
            msg = "Session id is none"
            raise SessionError(msg)

        # Auth fix 7/25/26 writing this so i can remember to check here if
        # i encounter problems; session stuff has historically been problematic
        # and i didnt really test this fix
        session = Session(session_id, self.users, self.sessions)
        if not session.valid:
            msg = "Invalid session"
            raise SessionError(msg)
        return session


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
