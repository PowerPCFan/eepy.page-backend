import logging
from unittest.mock import MagicMock  # type: ignore[import-untyped]

import pyotp
import pytest

from database.exceptions import UserNotExistError
from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from security.session import (
    InvalidToken,
    Session,
    SessionError,
    SessionFlagError,
    SessionPermissonError,
)

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

valid_session.permissions = ["admin"]
valid_session.flags = ["store"]

invalid_session = MagicMock(spec=Session)
invalid_session.valid = False


def test_requires_auth_valid_session() -> None:
    @Session.requires_auth
    def mock_function(session) -> str:
        return "Executed"

    result = mock_function(session=valid_session)
    assert result == "Executed"


def test_requires_auth_invalid_session() -> None:
    @Session.requires_auth
    def mock_function(session) -> str:
        return "Executed"

    with pytest.raises(SessionError):
        mock_function(session=invalid_session)


def test_requires_perms_valid() -> None:
    @Session.requires_permission("admin")
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
