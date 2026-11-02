from collections.abc import Callable
from typing import Any

import pymongo
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.invitation import Invites
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import USER_MIGRATION_VERSION, Users, UserType
from dns_.dns import DNS
from mail.email import Email, normalize_email_address
from security.encryption import Encryption
from security.risk import create_default_risk
from server.routes.auth import Auth, username_regex
from server.routes.models.user import LoginRequest, MfaRecovery
from server.routes.user import User as UserRoutes


class TestUsernameValidation:
    @pytest.mark.parametrize(
        "valid_username",
        [
            "abc",  # minimum allowed length (3)
            "a_b",
            "a-b",
            "user123",
            "AwesomeUser",
            "test_user",
            "cool-dev-name",
            "user_name-123",
            "12345",
            "a" * 32,  # maximum allowed length (32)
            "user_with_exactly_32_characters",
        ],
    )
    def test_valid_usernames_match_regex(self, valid_username: str) -> None:
        assert username_regex.match(valid_username) is not None

    @pytest.mark.parametrize(
        "invalid_username",
        [
            "",  # empty
            "a",  # too short (<3)
            "ab",  # too short (<3)
            "a" * 33,  # too long (>32)
            "user@email.com",  # contains @ symbol
            "user.name",  # contains dot
            "user name",  # contains space
            " user",  # leading space
            "user ",  # trailing space
            "user!name",  # exclamation mark
            "user#123",  # hash
            "user$money",  # dollar sign
            "user%percent",  # percent
            "user^caret",  # caret
            "user&and",  # ampersand
            "user*star",  # asterisk
            "user(paren)",  # parentheses
            "user+plus",  # plus
            "user=equal",  # equals
            "user[bracket]",  # brackets
            "user/slash",  # slash
            "user\\backslash",  # backslash
            "user:colon",  # colon
            "user;semicolon",  # semicolon
            "user?question",  # question mark
            "käyttäjä",  # non-ASCII unicode
            "user✨",  # emoji
            "abc\n",  # trailing newline rejected by \Z
        ],
    )
    def test_invalid_usernames_fail_regex(self, invalid_username: str) -> None:
        assert username_regex.fullmatch(invalid_username) is None
        assert username_regex.match(invalid_username) is None


class TestCaseInsensitiveUsernameLogin:
    @pytest.mark.parametrize(
        "username_variant",
        [
            "testing",  # exact lowercase
            "Testing",  # capitalized
            "TESTING",  # all uppercase
            "tEsTiNg",  # mixed case 1
            "TeStInG",  # mixed case 2
            " testing ",  # with whitespace
        ],
    )
    def test_case_insensitive_username_finds_user(
        self,
        users: Users,
        test_user: UserType,
        username_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(username_variant)

        assert matched_user is not None
        assert matched_user["_id"] == test_user["_id"]

    @pytest.mark.parametrize(
        "username_variant",
        [
            "testing",
            "Testing",
            "TESTING",
            "tEsTiNg",
        ],
    )
    def test_case_insensitive_username_password_check(
        self,
        users: Users,
        encryption: Encryption,
        username_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(username_variant)
        assert matched_user is not None
        assert matched_user.get("password") is not None
        assert encryption.check_password("testing", matched_user["password"]) is True  # pyright: ignore[reportArgumentType]


class TestCaseInsensitiveEmailLogin:
    @pytest.mark.parametrize(
        "email_variant",
        [
            "testing@email.com",  # exact lowercase
            "Testing@email.com",  # capitalized username
            "TESTING@EMAIL.COM",  # all uppercase
            "Testing@Email.Com",  # title case
            "tEsTiNg@EmAiL.cOm",  # mixed case
            " testing@email.com ",  # with whitespace
        ],
    )
    def test_case_insensitive_email_finds_user(
        self,
        users: Users,
        test_user: UserType,
        email_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(email_variant)

        assert matched_user is not None
        assert matched_user["_id"] == test_user["_id"]

    @pytest.mark.parametrize(
        "email_variant",
        [
            "testing@email.com",
            "Testing@email.com",
            "TESTING@EMAIL.COM",
            "tEsTiNg@EmAiL.cOm",
        ],
    )
    def test_case_insensitive_email_password_check(
        self,
        users: Users,
        encryption: Encryption,
        email_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(email_variant)
        assert matched_user is not None
        assert matched_user.get("password") is not None
        assert encryption.check_password("testing", matched_user["password"]) is True  # pyright: ignore[reportArgumentType]


class TestInvalidLoginIdentifiers:
    @pytest.mark.parametrize(
        "nonexistent_identifier",
        [
            "nonexistent_user",
            "nobody@example.com",
            "testin",
            "testingg",
            "wrong@email.com",
        ],
    )
    def test_nonexistent_identifier_returns_none(
        self,
        users: Users,
        nonexistent_identifier: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(nonexistent_identifier)
        assert matched_user is None

    def test_valid_identifier_with_wrong_password_fails(
        self,
        users: Users,
        encryption: Encryption,
    ) -> None:
        matched_user = users.find_user_by_identifier("testing")
        assert matched_user is not None
        assert encryption.check_password("wrong_password", matched_user["password"]) is False  # pyright: ignore[reportArgumentType]

        matched_email_user = users.find_user_by_identifier("testing@email.com")
        assert matched_email_user is not None
        assert encryption.check_password("wrong_password", matched_email_user["password"]) is False  # pyright: ignore[reportArgumentType]


def test_username_case_collision_migration_and_exact_id_precedence(
    users: Users,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    lower_hash = Encryption.sha256("alice")

    user_lower = insert_test_user(
        {
            "_id": Encryption.sha256("alice"),
            "email": encryption.encrypt("alice1@example.com"),
            "email-hash": Encryption.sha256("alice1@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("alice1@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("alice"),
            "username": lower_hash,
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
    user_upper = insert_test_user(
        {
            "_id": Encryption.sha256("Alice"),
            "email": encryption.encrypt("alice2@example.com"),
            "email-hash": Encryption.sha256("alice2@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("alice2@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("Alice"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
        },
    )

    stored_upper_before = users.find_item({"_id": user_upper["_id"]})
    assert stored_upper_before is not None
    migrated_upper = users.perform_migrations(stored_upper_before)  # pyright: ignore[reportArgumentType]
    assert "username" not in migrated_upper
    stored_upper_after = users.find_item({"_id": user_upper["_id"]})
    assert stored_upper_after is not None
    assert "username" not in stored_upper_after

    found_upper = users.find_user_by_identifier("Alice")
    assert found_upper is not None
    assert found_upper["_id"] == user_upper["_id"]

    found_lower = users.find_user_by_identifier("alice")
    assert found_lower is not None
    assert found_lower["_id"] == user_lower["_id"]


def test_login_route_ordering_email_login_and_mfa_gate(
    mongo_client: pymongo.MongoClient,
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    pw_hash = encryption.create_password("correct-horse")

    insert_test_user(
        {
            "_id": Encryption.sha256("disabled_acc"),
            "email": encryption.encrypt("disabled@example.com"),
            "email-hash": Encryption.sha256("disabled@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("disabled@example.comsupahcool"),
            "password": pw_hash,
            "display-name": encryption.encrypt("disabled_acc"),
            "username": Encryption.sha256("disabled_acc"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": False,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": {
                "score": 85,
                "locked": False,
                "disabled": True,
                "disable_reasons": ["Auto"],
                "flags": {},
            },
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    mfa_user = insert_test_user(
        {
            "_id": Encryption.sha256("mfa_acc"),
            "email": encryption.encrypt("mfa@example.com"),
            "email-hash": Encryption.sha256("mfa@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("mfa@example.comsupahcool"),
            "password": pw_hash,
            "display-name": encryption.encrypt("mfa_acc"),
            "username": Encryption.sha256("mfa_acc"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "totp": {"verified": True, "key": encryption.encrypt("JBSWY3DPEHPK3PXP"), "recovery": []},
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    active_user = insert_test_user(
        {
            "_id": Encryption.sha256("ActiveUser"),
            "email": encryption.encrypt("Active.User@gmail.com"),
            "email-hash": Encryption.sha256("active.user@gmail.comsupahcool"),
            "normalized-email-hash": Encryption.sha256(normalize_email_address("Active.User@gmail.com") + "supahcool"),
            "password": pw_hash,
            "display-name": encryption.encrypt("ActiveUser"),
            "username": Encryption.sha256("activeuser"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "totp": {},
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    invites = Invites(mongo_client)
    dns = DNS(domains)
    auth = Auth(users, sessions, invites, email, dns)
    auth.captcha.verify = lambda *_args, **_kwargs: True  # type: ignore[method-assign]

    req = Request({"type": "http", "headers": [(b"user-agent", b"pytest")], "client": ("198.51.100.77", 12345)})

    with pytest.raises(HTTPException) as exc_info:
        auth.login(
            req,
            LoginRequest(username="disabled_acc", password="wrong-password"),
            x_captcha_code="ok",
            x_device_id="dev-attacker",
        )
    assert exc_info.value.status_code == 401
    assert users.ip_activity.find_items({}) == []

    with pytest.raises(HTTPException) as exc_info:
        auth.login(
            req,
            LoginRequest(username="disabled_acc", password="correct-horse"),
            x_captcha_code="ok",
        )
    assert exc_info.value.status_code == 403
    assert (exc_info.value.headers or {}).get("X-Auth-Error") == "account_disabled"

    with pytest.raises(HTTPException) as exc_info:
        auth.login(
            req,
            LoginRequest(username="mfa_acc", password="correct-horse"),
            x_captcha_code="ok",
            x_mfa_code=None,
            x_device_id="dev-mfa-test",
        )
    assert exc_info.value.status_code == 412
    assert users.ip_activity.find_items({}) == []
    stored_mfa = users.find_item({"_id": mfa_user["_id"]})
    assert stored_mfa is not None
    assert stored_mfa["risk"].get("device_id") is None

    resp = auth.login(
        req,
        LoginRequest(username="Active.User@gmail.com", password="correct-horse"),
        x_captcha_code="ok",
        x_device_id="dev-active-01",
    )
    assert resp.status_code == 200
    assert users.ip_activity.find_item({"_id": f"198.51.100.77_{active_user['_id']}"}) is not None
    stored_active = users.find_item({"_id": active_user["_id"]})
    assert stored_active is not None
    assert stored_active["risk"]["device_id"] == "dev-active-01"


def test_password_and_mfa_recovery_by_username_and_email_and_password_first_order(
    mongo_client: pymongo.MongoClient,
    users: Users,
    sessions: Sessions,
    codes: Codes,
    domains: Domains,
    email: Email,
    rewards: Rewards,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pw_hash = encryption.create_password("my-secret-pass")

    insert_test_user(
        {
            "_id": Encryption.sha256("nomfauser"),
            "email": encryption.encrypt("nomfa@example.com"),
            "email-hash": Encryption.sha256("nomfa@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("nomfa@example.comsupahcool"),
            "password": pw_hash,
            "display-name": encryption.encrypt("nomfauser"),
            "username": Encryption.sha256("nomfauser"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "totp": {},
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    mfa_user = insert_test_user(
        {
            "_id": Encryption.sha256("WithMfaUser"),
            "email": encryption.encrypt("With.Mfa@gmail.com"),
            "email-hash": Encryption.sha256("with.mfa@gmail.comsupahcool"),
            "normalized-email-hash": Encryption.sha256(normalize_email_address("With.Mfa@gmail.com") + "supahcool"),
            "password": pw_hash,
            "display-name": encryption.encrypt("WithMfaUser"),
            "username": Encryption.sha256("withmfauser"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "totp": {
                "verified": True,
                "key": encryption.encrypt("JBSWY3DPEHPK3PXP"),
                "recovery": [encryption.encrypt("backup-code-1111"), encryption.encrypt("backup-code-2222")],
            },
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    insert_test_user(
        {
            "_id": Encryption.sha256("oauth_only"),
            "email": encryption.encrypt("oauth_only@example.com"),
            "email-hash": Encryption.sha256("oauth_only@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("oauth_only@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("oauth_only"),
            "username": Encryption.sha256("oauth_only"),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "totp": {},
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    sent_to: list[str] = []
    monkeypatch.setattr(
        "mail.email.resend.Emails.send",
        lambda payload: sent_to.append(payload["to"]),
    )

    assert email.send_password_code("WithMfaUser") is True
    assert email.send_password_code("With.Mfa@gmail.com") is True
    assert sent_to == ["With.Mfa@gmail.com", "With.Mfa@gmail.com"]

    user_routes = UserRoutes(
        table=users,
        session_table=sessions,
        invite_table=Invites(mongo_client),
        email=email,
        codes=codes,
        dns=DNS(domains),
        rewards=rewards,
    )
    req = Request({"type": "http", "headers": [], "client": ("198.51.100.1", 50000)})

    with pytest.raises(HTTPException) as exc_info:
        user_routes.delete_mfa_with_username_pass(
            req,
            MfaRecovery(username="nomfauser", password="wrong-password"),
            x_backup_code="backup-code-1111",
        )
    assert exc_info.value.status_code == 401

    with pytest.raises(HTTPException) as exc_info:
        user_routes.delete_mfa_with_username_pass(
            req,
            MfaRecovery(username="oauth_only", password="any-password"),
            x_backup_code="backup-code-1111",
        )
    assert exc_info.value.status_code == 401

    with pytest.raises(HTTPException) as exc_info:
        user_routes.delete_mfa_with_username_pass(
            req,
            MfaRecovery(username="nomfauser", password="my-secret-pass"),
            x_backup_code="backup-code-1111",
        )
    assert exc_info.value.status_code == 412

    user_routes.delete_mfa_with_username_pass(
        req,
        MfaRecovery(username="With.Mfa@gmail.com", password="my-secret-pass"),
        x_backup_code="backup-code-1111",
    )
    updated_mfa_user = users.find_item({"_id": mfa_user["_id"]})
    assert updated_mfa_user is not None
    assert "totp" not in updated_mfa_user
