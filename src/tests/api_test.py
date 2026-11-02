from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from database.tables.users import USER_MIGRATION_VERSION, Users, UserType
from security.api import Api, ApiError, ApiKeyLimitError, ApiPermissionError, ApiRangeError
from security.encryption import Encryption
from security.session import Session

valid_key: Api = MagicMock(spec=Api)
valid_key.valid = True

valid_key.permissions = ["modify", "register", "list"]
valid_key.affected_domains = ["test.eepy.page", "affected.eepy.page"]

invalid_key: Api = MagicMock(spec=Api)
invalid_key.valid = False


@pytest.mark.order(-1)
class TestUserApi:
    def test_creation(self, test_session: Session, users: Users, test_user: UserType) -> None:
        Api.create(
            test_user["_id"],
            users,
            "test key",
            ["register", "modify"],
            domains=["test.eepy.page"],
        )

        with pytest.raises(ApiKeyLimitError):
            Api.create(
                test_user["_id"],
                users,
                "second key",
                ["register"],
                domains=["test.eepy.page"],
            )

        with pytest.raises(PermissionError):
            Api.create(
                test_user["_id"],
                users,
                "test key",
                ["register"],
                domains=["domain-that-isnt-owned.eepy.page"],
            )

        users.modify_document(
            filter={"_id": test_user["_id"]},
            operation="$set",
            key="api-keys",
            value={},
        )

    def test_key_permissions(self, test_user: UserType, users: Users) -> None:
        key = Api.create(
            test_user["_id"],
            users,
            "test key",
            ["register", "modify"],
            domains=["test.eepy.page"],
        )

        api = Api(key, users)

        @Api.requires_auth
        @Api.requires_permission("modify")
        def test_modify(api: Api, domain: str) -> bool:
            return True

        @Api.requires_auth
        @Api.requires_permission("register")
        def test_register(api: Api) -> bool:
            return True

        @Api.requires_auth
        @Api.requires_permission("delete")
        def test_delete(api: Api, domain: str) -> bool:
            return True

        @Api.requires_auth
        @Api.requires_permission("list")
        def test_list(api: Api) -> bool:
            return True

        # Test without any permissions
        api.permissions = []
        with pytest.raises(ApiPermissionError):
            test_modify(api, domain="test")

        with pytest.raises(ApiPermissionError):
            test_register(api)

        with pytest.raises(ApiPermissionError):
            test_delete(api, domain="test")

        with pytest.raises(ApiPermissionError):
            test_list(api)

        # individually test permissions and domains
        api.permissions.append("modify")
        assert test_modify(api, domain="test.eepy.page")

        with pytest.raises(ApiRangeError):
            test_modify(api, domain="unknown-domain.eepy.page")

        api.permissions.append("delete")
        assert test_delete(api, domain="test.eepy.page")

        with pytest.raises(ApiRangeError):
            test_delete(api, domain="unknown-domain.eepy.page")

        api.permissions.append("register")
        assert test_register(api)

        api.permissions.append("list")

        assert test_list(api)


def test_requires_auth_valid_key() -> None:
    @Api.requires_auth
    def mock_function(api) -> str:
        return "Executed"

    result = mock_function(api=valid_key)
    assert result == "Executed"


def test_requires_auth_invalid_key() -> None:
    @Api.requires_auth
    def mock_function(api) -> str:
        return "Executed"

    with pytest.raises(ApiError):
        mock_function(api=invalid_key)


def test_requires_perms_valid() -> None:
    @Api.requires_auth
    @Api.requires_permission("register")
    def mock_function(api) -> str:
        return "Executed"

    result = mock_function(api=valid_key)
    assert result == "Executed"


def test_requires_perms_invalid() -> None:
    @Api.requires_auth
    @Api.requires_permission("delete")
    def mock_function(api) -> str:
        return "Executed"

    with pytest.raises(ApiPermissionError):
        mock_function(api=valid_key)


def test_modification_domain() -> None:
    @Api.requires_auth
    @Api.requires_permission("modify")
    def mock_function(api, domain) -> str:
        return "Executed"

    result = mock_function(api=valid_key, domain="affected.eepy.page")
    assert result == "Executed"


def test_invalid_modification_domain() -> None:
    @Api.requires_auth
    @Api.requires_permission("modify")
    def mock_function(api, domain) -> str:
        return "Executed"

    with pytest.raises(ApiRangeError):
        mock_function(api=valid_key, domain="unaffected.eepy.page")


def test_disabled_account_rejected_on_api_key(
    users: Users,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    raw_api_key = "$APIV2=0123456789abcdef0123456789abcdef"
    key_hash = Encryption.sha256(raw_api_key + "eepy.page")
    user_id = Encryption.sha256("disabled_api_user")

    insert_test_user(
        {
            "_id": user_id,
            "email": encryption.encrypt("u@example.com"),
            "email-hash": Encryption.sha256("u@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("u@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt("disabled_api_user"),
            "username": user_id,
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [{"name": "sub.eepy.page", "type": "A", "ip": ["1.2.3.4"], "registered": 1700000000}],
            "owned-tlds": ["eepy.page"],
            "api-keys": {
                key_hash: {
                    "string": encryption.encrypt(raw_api_key),
                    "perms": ["modify", "register", "delete", "list"],
                    "domains": ["*"],
                    "comment": "key",
                },
            },
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

    api = Api(raw_api_key, users)
    assert api.valid is False

    @Api.requires_auth
    def protected_api_call(api: Api) -> str:
        return "ok"

    with pytest.raises(ApiError):
        protected_api_call(api=api)

