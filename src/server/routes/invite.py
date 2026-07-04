import logging

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException

from database.exceptions import InviteException, UserNotExistError
from database.tables.invitation import Invites as InviteTable
from database.tables.sessions import Sessions as SessionTable
from database.tables.users import Users as UsersTable
from security.convert import Convert
from security.session import Session
from server.routes.models.invite import InviteCreate

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("eepy.page")


class Invite:
    def __init__(
        self,
        table: UsersTable,
        sessions: SessionTable,
        invites: InviteTable,
    ) -> None:
        converter.init_vars(table, sessions)
        self.table: UsersTable = table
        self.invites: InviteTable = invites

        self.router = APIRouter(prefix="/invite")

        self.router.add_api_route(
            "/create",
            self.create,
            methods=["POST"],
            responses={
                200: {"description": "Invite code created"},
                404: {"description": "User does not exist"},
                409: {"description": "Invite limit (3) reached"},
                460: {"description": "Invalid session"},
            },
            tags=["invite"],
        )

        logger.info("Initialized")

    @Session.requires_auth
    @Session.requires_permission(permission="invite")
    def create(self, session: Session = Depends(converter.create)) -> InviteCreate:
        try:
            code: str = self.invites.create(session.username)
        except InviteException:
            raise HTTPException(status_code=409)
        except UserNotExistError:
            raise HTTPException(status_code=404)

        return {"code": code}  # type: ignore[return-value]
