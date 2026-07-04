import json
import logging
import os
import time
from typing import TypedDict

import requests  # type: ignore[import-untyped]
from fastapi import Request
from ipinfo import Handler  # type: ignore[import-untyped]

from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from mail.email import Email
from security.encryption import Encryption
from security.session import Session, SessionError

logger = logging.getLogger("eepy.page")


class EmailError(Exception): ...


class DuplicateAccount(Exception): ...


class GoogleUserResponse(TypedDict):
    sub: str
    name: str
    given_name: str
    family_name: str
    picture: str
    email: str
    email_verified: bool


class OAuth:
    def __init__(self, users: Users, sessions: Sessions, emails: Email) -> None:
        self.google_client_id: str | None = os.getenv("GOOGLE_CLIENT_ID")
        self.google_client_secret: str | None = os.getenv("GOOGLE_CLIENT_SECRET")

        if not self.google_client_id or not self.google_client_secret:
            logger.error("No client id or client secret mentioned")

        self.sessions: Sessions = sessions
        self.users: Users = users
        self.emails: Email = emails

    def get_google_callback_data(
        self,
        callback_url: str,
        code: str,
    ) -> GoogleUserResponse:
        logger.info(f"Checking google with code {code}")
        req = requests.post(
            "https://oauth2.googleapis.com/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "code": code,
                "client_id": self.google_client_id,
                "client_secret": self.google_client_secret,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
            timeout=5,
        )
        token: str | None = req.json().get("access_token")

        if token is None:
            logger.warning(
                f"Failed to get token for google sign in. {req.status_code} {req.text}",
            )
            msg = "Failed to get token for user"
            raise ValueError(msg)

        data: GoogleUserResponse = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        ).json()

        return data

    def create_google_session(
        self,
        request: Request,
        ipinfo_handler: Handler,
        code: str,
        callback_url: str,
        refer_code: str | None,
    ) -> tuple[str, str]:
        """Creates a session pair from a google auth callback

        :param request: the request object
        :type request: Request
        :param ipinfo_handler: an instance of ipinfo's handler class
        :type ipinfo_handler: Handler
        :param code: google auth code recieved as query param
        :type code: str
        :raises ValueError: if cannot upgrade code to token
        :raises SessionError: if cannot create session
        :return: a tuple (access_token, refresh_token)
        :rtype: Tuple[str, str]
        """

        data = self.get_google_callback_data(callback_url, code)

        if not data.get("email_verified", False):
            msg = "Google email not verified"
            raise EmailError(msg)

        email_hash: str = Encryption.sha256(data["email"] + "supahcool")
        target_user: UserType | None = self.users.find_user({"email-hash": email_hash})

        country = ipinfo_handler.getDetails(request.client.host).all  # type: ignore[union-attr]
        user_id = ""
        if target_user is None:
            user_id = self.users.create_user(
                username=data["email"],
                password=None,
                email=data["email"],
                language="en-US",
                country=country,
                time_signed_up=time.time(),
                email_instance=self.emails,
                target_url=request.headers.get("Origin", "https://www.eepy.page"),
                signup_method="google",
                skip_verification=True,
                refer_code=refer_code,
            )
        else:
            if not target_user.get("has-linked-google"):
                logger.info("User hasn't linked google... Giving an invalid response")
                logger.info(json.dumps(target_user, indent=2))
                msg = "User already has an account"
                raise DuplicateAccount(msg)

            user_id = target_user["_id"]

        session = Session.create(
            user_id,
            data["name"],
            None,
            request.client.host if request.client else "",
            request.headers.get("User-Agent", "Google sign in"),
            self.users,
            self.sessions,
            skip_mfa=True,
        )

        if not session["success"]:
            logger.error(f"Failed to create session for user {data['email']}")
            msg = "Failed to create session"
            raise SessionError(msg)

        return (session["access_token"], session["refresh_token"])  # pyright: ignore[reportReturnType]

    def link_google_account(
        self,
        session: Session,
        _request: Request,
        code: str,
        callback_url: str,
    ) -> bool:
        data: GoogleUserResponse = self.get_google_callback_data(callback_url, code)

        if session.user_cache_data.get(
            "registered-with",
        ) == "google" or session.user_cache_data.get("has-linked-google"):
            logger.warning("User already has registered with google")
            return False

        if not data.get("email_verified", False):
            logger.warning("Google email not verified!")
            msg = "Google email not verified"
            raise EmailError(msg)

        if data.get("email") != self.users.encryption.decrypt(
            session.user_cache_data["email"],
        ):
            logger.warning(
                f"Google email {data.get('email')} does not match users email!",
            )
            msg = "Email mismatch!"
            raise ValueError(msg)

        self.users.modify_document(
            filter={"_id": session.user_id},
            operation="$set",
            key="has-linked-google",
            value=True,
        )
        return True
