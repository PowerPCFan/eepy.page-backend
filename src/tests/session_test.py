import logging
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock  # type: ignore[import-untyped]

import pymongo
import pyotp
import pytest
from starlette.requests import Request

from database.exceptions import UserNotExistError
from database.tables.domains import Domains
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.users import USER_MIGRATION_VERSION, Users, UserType
from dns_.dns import DNS
from mail.email import Email
from security.encryption import Encryption
from security.risk import create_default_risk
from security.session import (
    InvalidToken,
    Session,
    SessionError,
    SessionFlagError,
    SessionPermissonError,
)
from server.routes.auth import Auth

logger = logging.getLogger(__name__)


class TestCreation:
    def test_creation(self, test_user: UserType, users: Users, sessions: Sessions) -> None:
        assert Session.create(
            username=test_user["_id"],
            real_username="testing",
            mfa_code=None,
            ip="192.168.1.1",
            user_agent="eepy.page-pytest-suite",
            users=users,
            session_table=sessions,
        )["success"]

        with pytest.raises(UserNotExistError):
            Session.create(
                username="random-user-id",
                real_username="testing",
                mfa_code=None,
                ip="192.168.1.1",
                user_agent="eepy.page-pytest-suite",
                users=users,
                session_table=sessions,
            )["success"]

    def test_mfa_setup(self, test_user: UserType, users: Users, sessions: Sessions) -> None:
        session_data = Session.create(
            username=test_user["_id"],
            real_username="testing",
            mfa_code=None,
            ip="192.168.1.1",
            user_agent="eepy.page-pytest-suite",
            users=users,
            session_table=sessions,
        )

        if not session_data["access_token"]:
            logger.error("Failed to get session data")
            return

        session = Session(session_data["access_token"], users, sessions)
        mfa_result = session.create_2fa()
        url = mfa_result["url"]
        backup = mfa_result["codes"]

        refreshed_user = users.find_user({"_id": test_user["_id"]})
        session.user_cache_data = refreshed_user  # type: ignore

        code = pyotp.TOTP(pyotp.parse_uri(url).secret).now()
        assert session.verify_2fa(code)

        session.remove_mfa(backup_code=backup[0], mfa_code=None)

    def test_refresh(
        self,
        test_user: UserType,
        test_session: Session,
        test_session_refresh: str,
        sessions: Sessions,
        users: Users,
    ) -> None:
        logger.info(test_user["country"])
        old_access_token = test_session.token
        assert not Session.refresh(
            old_access_token,
            sessions,
            "BACKEND_TESTING",
            test_user["country"]["ip"],
        )

        result = Session.refresh(
            test_session_refresh,
            sessions,
            "BACKEND_TESTING",
            test_user["country"]["ip"],
        )

        if not result:
            pytest.fail("Invalid session refresh!")

        access, _refresh = result

        assert not Session(old_access_token, users, sessions).valid
        assert Session(access, users, sessions).valid
        assert not Session.refresh(
            test_session_refresh,
            sessions,
            "BACKEND_TESTING",
            test_user["country"]["ip"],
        )

    def test_object(self, test_session: Session, test_user: UserType, users: Users) -> None:
        assert test_session.user_id == test_session.user_cache_data["_id"]
        assert test_session.token_result != InvalidToken

        user = users.find_user({"_id": test_user["_id"]})
        assert user is not None

        assert test_session.user_cache_data == user

    def test_logging_out(self, test_user: UserType, users: Users, sessions: Sessions) -> None:
        session_data = Session.create(
            username=test_user["_id"],
            real_username="testing",
            mfa_code=None,
            ip="192.168.1.1",
            user_agent="eepy.page-pytest-suite",
            users=users,
            session_table=sessions,
        )

        if not session_data["access_token"]:
            logger.error("Failed to get session data")
            return

        session = Session(session_data["access_token"], users, sessions)
        assert session.delete(session.data["jti"])

    def test_attributes(self, test_session: Session) -> None:
        assert test_session.user_id == test_session.username  # backwards compatability

    def test_missing_jwt_key_fails_before_signing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("JWT_KEY", raising=False)

        with pytest.raises(RuntimeError, match="JWT_KEY"):
            Session.create_session_pair(
                "test-user",
                "eepy.page-pytest-suite",
                "192.168.1.1",
                MagicMock(spec=Sessions),
            )


valid_session = MagicMock(spec=Session)
valid_session.valid = True

valid_session.permissions = ["userdetails"]
valid_session.flags = ["store"]

invalid_session = MagicMock(spec=Session)
invalid_session.valid = False


def test_requires_auth_valid_session() -> None:
    @Session.requires_auth
    def mock_function(session) -> str:
        return "Executed"

    result = mock_function(session=valid_session)
    assert result == "Executed"


def test_requires_auth_underscore_session() -> None:
    @Session.requires_auth
    def mock_function(_session) -> str:
        return "Executed"

    result = mock_function(_session=valid_session)
    assert result == "Executed"


def test_requires_auth_invalid_session() -> None:
    @Session.requires_auth
    def mock_function(session) -> str:
        return "Executed"

    with pytest.raises(SessionError):
        mock_function(session=invalid_session)


def test_requires_perms_valid() -> None:
    @Session.requires_permission("userdetails")
    def mock_function(session) -> str:
        return "Executed"

    result = mock_function(session=valid_session)
    assert result == "Executed"


def test_requires_perms_invalid() -> None:
    @Session.requires_permission("blogs")
    def mock_function(session) -> str:
        return "Executed"

    with pytest.raises(SessionPermissonError):
        mock_function(session=valid_session)


def test_requires_flag_valid() -> None:
    @Session.requires_flag(flag="store")
    def mock_function(session) -> str:
        return "Executed"

    result = mock_function(session=valid_session)
    assert result == "Executed"


def test_requires_flag_invalid() -> None:
    @Session.requires_flag(flag="apex-domains")
    def mock_function(session) -> str:
        return "Executed"

    with pytest.raises(SessionFlagError):
        mock_function(session=valid_session)


def test_disabled_account_rejected_on_session_refresh(
    users: Users,
    sessions: Sessions,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    user_id = Encryption.sha256("disabled_session_user")

    insert_test_user(
        {
            "_id": user_id,
            "email": encryption.encrypt("disabled_session@example.com"),
            "email-hash": Encryption.sha256("disabled_session@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("disabled_session@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("disabled_session_user"),
            "username": user_id,
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": {
                "score": 85,
                "locked": False,
                "disabled": True,
                "disable_reasons": ["Auto-disabled"],
                "flags": {},
            },
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    access_token, refresh_token = Session.create_session_pair(
        user_id,
        "pytest-agent",
        "198.51.100.1",
        sessions,
    )
    assert access_token
    refreshed = Session.refresh(
        refresh_token,
        sessions,
        "pytest-agent",
        "198.51.100.1",
        users=users,
    )
    assert refreshed is False
    assert sessions.find_items({"owner": user_id, "type": "refresh"}) == []


def test_session_delete_and_logout_for_both_refresh_and_access_types(
    mongo_client: pymongo.MongoClient,
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    user_id = Encryption.sha256("session_owner")

    insert_test_user(
        {
            "_id": user_id,
            "email": encryption.encrypt("owner@example.com"),
            "email-hash": Encryption.sha256("owner@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("owner@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("session_owner"),
            "username": user_id,
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    access_1, _refresh_1 = Session.create_session_pair(user_id, "agent-1", "198.51.100.1", sessions)
    access_2, _refresh_2 = Session.create_session_pair(user_id, "agent-2", "198.51.100.2", sessions)
    assert access_1 is not None
    assert access_2 is not None

    session_1 = Session(access_1, users, sessions)
    session_2 = Session(access_2, users, sessions)

    access_2_doc = sessions.get_session(session_2.data["jti"])
    assert access_2_doc is not None
    refresh_2_id = access_2_doc["parent"]  # pyright: ignore[reportGeneralTypeIssues]

    invites = Invites(mongo_client)
    dns = DNS(domains)
    auth = Auth(users, sessions, invites, email, dns)

    req_specific = Request(
        {
            "type": "http",
            "headers": [
                (b"specific", b"true"),
                (b"id", refresh_2_id.encode()),
            ],
            "client": ("198.51.100.1", 50000),
        },
    )
    auth.logout(req_specific, session=session_1, x_device_id="dev-logout-1")
    assert sessions.get_session(refresh_2_id) is None
    assert sessions.get_session(session_2.data["jti"]) is None
    assert users.recent_logouts.find_items({"user_id": user_id}) == []

    req_normal = Request(
        {
            "type": "http",
            "headers": [],
            "client": ("198.51.100.1", 50000),
        },
    )
    auth.logout(req_normal, session=session_1, x_device_id="dev-logout-1")
    assert sessions.find_items({"owner": user_id}) == []
    logout_rows = users.recent_logouts.find_items({"user_id": user_id})
    assert len(logout_rows) == 1
    assert logout_rows[0]["user_id"] == user_id
