import logging
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pyotp
import pytest
from starlette.requests import Request

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from tests.conftest import TestUserFactory

from database.exceptions import UserNotExistError
from database.models import User, UserPermissions, UserRiskProfile
from database.tables.domains import Domains
from database.tables.invitation import Invites
from database.tables.sessions import Sessions
from database.tables.users import Users
from dns_.dns import DNS
from mail.email import Email
from security.encryption import Encryption
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
    def test_creation(self, test_user: User, users: Users, sessions: Sessions) -> None:
        assert Session.create(
            username=test_user.id,
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

    def test_mfa_setup(self, test_user: User, users: Users, sessions: Sessions) -> None:
        session_data = Session.create(
            username=test_user.id,
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

        refreshed_user = users.get_user(test_user.id)
        assert refreshed_user is not None
        session.user_cache_data = refreshed_user

        code = pyotp.TOTP(pyotp.parse_uri(url).secret).now()
        assert session.verify_2fa(code)

        session.remove_mfa(backup_code=backup[0], mfa_code=None)

    def test_refresh(
        self,
        test_user: User,
        test_session: Session,
        test_session_refresh: str,
        sessions: Sessions,
        users: Users,
    ) -> None:
        logger.info(test_user.country)
        old_access_token = test_session.token
        assert not Session.refresh(
            old_access_token,
            sessions,
            "BACKEND_TESTING",
            test_user.country["ip"],
        )

        result = Session.refresh(
            test_session_refresh,
            sessions,
            "BACKEND_TESTING",
            test_user.country["ip"],
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
            test_user.country["ip"],
        )

    def test_object(self, test_session: Session, test_user: User, users: Users) -> None:
        assert test_session.user_cache_data is not None
        assert test_session.user_id == test_session.user_cache_data.id
        assert test_session.token_result != InvalidToken

        user = users.get_user(test_user.id)
        assert user is not None

        assert test_session.user_cache_data == user

    def test_logging_out(self, test_user: User, users: Users, sessions: Sessions) -> None:
        session_data = Session.create(
            username=test_user.id,
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

    def test_missing_jwt_key_fails_before_signing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("JWT_KEY", raising=False)

        with pytest.raises(RuntimeError, match="JWT_KEY"):
            Session.create_session_pair(
                "test-user",
                "eepy.page-pytest-suite",
                "192.168.1.1",
                MagicMock(spec=Sessions),
            )


@pytest.fixture
def valid_session(
    users: Users,
    sessions: Sessions,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> Session:
    user_id = Encryption.sha256("session_decorator_test_user")
    insert_test_user(
        id=user_id,
        email=encryption.encrypt("session_decorator@example.com"),
        email_hash=encryption.hash_email("session_decorator@example.com"),
        normalized_email_hash=encryption.hash_email("session_decorator@example.com"),
        display_name=encryption.encrypt("session_decorator_test_user"),
        username=user_id,
        verified=True,
        feature_flags={"store": True, "apex-domains": False},
        permissions=UserPermissions(
            user_id=user_id,
            admin_enabled=True,
            admin_userdetails=True,
        ),
    )
    access_token, _ = Session.create_session_pair(user_id, "pytest-agent", "198.51.100.1", sessions)
    assert access_token is not None
    return Session(access_token, users, sessions)


@pytest.fixture
def invalid_session(users: Users, sessions: Sessions) -> Session:
    return Session("invalid.jwt.token", users, sessions)


def test_requires_auth_valid_session(valid_session: Session) -> None:
    @Session.requires_auth
    def protected(session: Session) -> str:
        return "Executed"

    assert protected(session=valid_session) == "Executed"


def test_requires_auth_underscore_session(valid_session: Session) -> None:
    @Session.requires_auth
    def protected(_session: Session) -> str:
        return "Executed"

    assert protected(_session=valid_session) == "Executed"


def test_requires_auth_invalid_session(invalid_session: Session) -> None:
    @Session.requires_auth
    def protected(session: Session) -> str:
        return "Executed"

    with pytest.raises(SessionError):
        protected(session=invalid_session)


def test_requires_perms_valid(valid_session: Session) -> None:
    @Session.requires_permission("userdetails")
    def protected(session: Session) -> str:
        return "Executed"

    assert protected(session=valid_session) == "Executed"


def test_requires_perms_invalid(valid_session: Session) -> None:
    @Session.requires_permission("blogs")
    def protected(session: Session) -> str:
        return "Executed"

    with pytest.raises(SessionPermissonError):
        protected(session=valid_session)


def test_requires_flag_valid(valid_session: Session) -> None:
    @Session.requires_flag(flag="store")
    def protected(session: Session) -> str:
        return "Executed"

    assert protected(session=valid_session) == "Executed"


def test_requires_flag_invalid(valid_session: Session) -> None:
    @Session.requires_flag(flag="apex-domains")
    def protected(session: Session) -> str:
        return "Executed"

    with pytest.raises(SessionFlagError):
        protected(session=valid_session)


def test_disabled_account_rejected_on_session_refresh(
    users: Users,
    sessions: Sessions,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> None:
    user_id = Encryption.sha256("disabled_session_user")

    insert_test_user(
        id=user_id,
        email=encryption.encrypt("disabled_session@example.com"),
        email_hash=encryption.hash_email("disabled_session@example.com"),
        normalized_email_hash=encryption.hash_email("disabled_session@example.com"),
        display_name=encryption.encrypt("disabled_session_user"),
        username=user_id,
        country={"country": "US"},
        created=1700000000,
        last_login=1700000000,
        verified=True,
        risk_profile=UserRiskProfile(
            user_id=user_id,
            score=85,
            disabled=True,
            disable_reasons=["Auto-disabled"],
        ),
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
    assert sessions.find_all(owner=user_id, type="refresh") == []


def test_session_delete_and_logout_for_both_refresh_and_access_types(
    db_engine: "Engine",
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> None:
    user_id = Encryption.sha256("session_owner")

    insert_test_user(
        id=user_id,
        email=encryption.encrypt("owner@example.com"),
        email_hash=encryption.hash_email("owner@example.com"),
        normalized_email_hash=encryption.hash_email("owner@example.com"),
        display_name=encryption.encrypt("session_owner"),
        username=user_id,
        country={"country": "US"},
        created=1700000000,
        last_login=1700000000,
        verified=True,
    )

    access_1, _refresh_1 = Session.create_session_pair(user_id, "agent-1", "198.51.100.1", sessions)
    access_2, _refresh_2 = Session.create_session_pair(user_id, "agent-2", "198.51.100.2", sessions)
    assert access_1 is not None
    assert access_2 is not None

    session_1 = Session(access_1, users, sessions)
    session_2 = Session(access_2, users, sessions)

    access_2_doc = sessions.get_session(session_2.data["jti"])
    assert access_2_doc is not None
    refresh_2_id = access_2_doc.parent
    assert refresh_2_id is not None

    invites = Invites(db_engine)
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
    assert users.recent_logouts.find_all(user_id=user_id) == []

    req_normal = Request(
        {
            "type": "http",
            "headers": [],
            "client": ("198.51.100.1", 50000),
        },
    )
    auth.logout(req_normal, session=session_1, x_device_id="dev-logout-1")
    assert sessions.find_all(owner=user_id) == []
    logout_rows = users.recent_logouts.find_all(user_id=user_id)
    assert len(logout_rows) == 1
    assert logout_rows[0].user_id == user_id
