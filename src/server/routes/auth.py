import logging
import os
import time
from typing import Annotated

import ipinfo
from fastapi import APIRouter, Depends, Header, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from database.exceptions import EmailException, UsernameException
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from dns_.dns import DNS
from mail.email import Email
from security.captcha import Captcha
from security.convert import Convert
from security.encryption import Encryption
from security.session import (
    REFRESH_AMOUNT,
    Session,
    SessionCreateStatus,
    SessionError,
    SessionPermissonError,
)
from server.routes.models.user import (
    LoginRequest,
    SignUp,
)

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("eepy.page")

is_debug = str(os.getenv("DEBUG_MODE", "False").lower().strip()) in {"true", "1", "y", "yes"}


class Auth:
    def __init__(
        self,
        table: Users,
        session_table: Sessions,
        invite_table: Invites,
        email: Email,
        dns: DNS,
    ) -> None:
        converter.init_vars(table, session_table)

        self.table: Users = table
        self.session_table: Sessions = session_table
        self.invites: Invites = invite_table
        self.email: Email = email
        self.dns: DNS = dns
        self.captcha: Captcha = Captcha(os.getenv("TURNSTILE_KEY") or "")

        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))  # type: ignore[arg-type]

        self.handler: ipinfo.Handler = ipinfo.getHandler(os.getenv("IPINFO_KEY"))

        self.router = APIRouter()

        self.router.add_api_route(
            "/login",
            self.login,
            methods=["POST"],
            responses={
                200: {
                    "description": "Login successfull",
                    "content": {
                        "application/json": {
                            "auth-token": "Token you can use for accessing things",
                            "refresh-token": "Refreshing your auth-token after it expires in 15 minutes",
                        },
                    },
                },
                400: {"description": "Account does not support password login"},
                404: {"description": "User not found"},
                401: {"description": "Invalid password"},
                412: {"description": "2FA code required to be passed in X-MFA-Code"},
                429: {"description": "Invalid captcha"},
            },
            tags=["account", "session"],
        )

        self.router.add_api_route(
            "/refresh",
            self.refresh,
            methods=["POST"],
            responses={
                200: {
                    "description": "Refreshed tokens successfully",
                    "content": {
                        "application/json": {
                            "auth-token": "Token you can use for accessing things",
                            "refresh-token": "Refreshing your auth-token after it expires in 15 minutes",
                        },
                    },
                },
                460: {"description": "Invalid key"},
            },
            tags=["account", "session"],
        )

        self.router.add_api_route(
            "/sign-up",
            self.sign_up,
            methods=["POST"],
            responses={
                200: {"description": "Sign up successfull"},
                422: {"description": "Email is already in use"},
                409: {"description": "Username is already in use"},
                429: {"description": "Invalid captcha"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/logout",
            self.logout,
            methods=["PATCH"],
            responses={
                404: {"description": "Session does not exist"},
                460: {"description": "Invalid session"},
                461: {"description": "User does not have access to use that session"},
            },
            status_code=200,
            tags=["account", "session"],
        )

        logger.info("Initialized")

    def login(
        self,
        request: Request,
        body: LoginRequest,
        x_captcha_code: Annotated[str, Header()],
        x_mfa_code: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        # plain_username can backfill display-name/username for older rows that only stored hashes.

        if not self.captcha.verify(x_captcha_code, request.client.host):  # type: ignore[union-attr]
            raise HTTPException(429, detail="Invalid captcha")

        plain_username = body.plain_username
        if Encryption.sha256(plain_username or "") != body.username_hash:
            logger.warning("Plain username doesnt match login... Setting as none")
            plain_username = None

        user_data: UserType | None = self.table.find_user({"_id": body.username_hash})

        if user_data is None:
            raise HTTPException(status_code=404, detail="User does not exist")

        if not user_data["verified"]:
            raise HTTPException(status_code=403, detail="Verification required")

        if user_data.get("password") is None:
            raise HTTPException(status_code=400, detail="Account does not support password login")

        ip: str = request.client.host  # type: ignore[union-attr]
        if not Encryption().check_password(body.password, user_data["password"]):  # pyright: ignore[reportArgumentType]
            raise HTTPException(status_code=401, detail="Invalid password")

        logger.info(f"Login attempt from {body.username_hash}")

        session_status: SessionCreateStatus = Session.create(
            username=body.username_hash,
            real_username=plain_username,
            mfa_code=x_mfa_code,
            ip=ip,
            user_agent=request.headers.get("User-Agent", "Unknown"),
            users=self.table,
            session_table=self.session_table,
        )

        if session_status["mfa_required"]:
            logger.debug("MFA error")
            raise HTTPException(status_code=412, detail="MFA required")

        if session_status["success"]:
            resp = JSONResponse({"auth-token": session_status["access_token"]})

            resp.set_cookie(
                "refresh-token",
                session_status["refresh_token"] or "invalid code",
                max_age=REFRESH_AMOUNT,
                path="/refresh",
                httponly=True,
                samesite="lax" if is_debug else "none",
                secure=not is_debug,
            )

            return resp
        raise HTTPException(status_code=500, detail="Failed to create session")

    def refresh(self, request: Request) -> JSONResponse:
        refresh_token: str | None = request.cookies.get("refresh-token")

        if not refresh_token:
            raise HTTPException(status_code=412, detail="refresh-token cookie missing")

        client = request.client
        if not client:
            raise HTTPException(status_code=500, detail="Invalid client?")

        session_data = Session.refresh(
            refresh_token,
            self.session_table,
            request.headers.get("User-Agent", ""),
            client.host,  # type: ignore[attr-defined]
        )

        if not session_data:
            raise HTTPException(status_code=465, detail="Failed to refresh token")

        access_token, refresh_token = session_data
        resp = JSONResponse({"auth-token": access_token})

        resp.set_cookie(
            "refresh-token",
            refresh_token,
            path="/refresh",
            httponly=True,
            max_age=REFRESH_AMOUNT,
            samesite="lax" if is_debug else "none",
            secure=not is_debug,
        )

        return resp

    def sign_up(
        self,
        request: Request,
        body: SignUp,
        x_captcha_code: Annotated[str, Header()],
    ) -> None:
        if not self.captcha.verify(x_captcha_code, request.client.host):  # type: ignore[union-attr]
            raise HTTPException(429, detail="Invalid captcha")

        country = self.handler.getDetails(request.client.host).all  # type: ignore[union-attr]
        from_url: str = request.headers.get("Origin", "https://www.eepy.page")

        refer = request.headers.get("x-refer-code")
        if refer:
            logger.info(f"Using refer {refer}")
        try:
            self.table.create_user(
                username=body.username,
                password=body.password,
                email=body.email,
                language=body.language,
                country=country,
                time_signed_up=round(time.time()),
                email_instance=self.email,
                target_url=from_url,
                refer_code=refer,
            )
        except EmailException:
            raise HTTPException(status_code=422, detail="Email already in use")
        except UsernameException:
            raise HTTPException(status_code=409, detail="Username already in use")

    @Session.requires_auth
    def logout(
        self,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> None:
        session_id: str
        if request.headers.get("specific") == "true":
            # The following will not be null if since if `specified` then id header must be present
            session_id = request.headers.get("id")  # type: ignore[assignment]
        else:
            session_id = session.data.get("jti", "")

        try:
            session.delete(session_id)
        except SessionError:
            raise HTTPException(404)
        except SessionPermissonError:
            raise HTTPException(461)
