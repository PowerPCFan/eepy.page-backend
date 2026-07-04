from unittest.mock import MagicMock  # type: ignore[import-untyped]

import pytest

from database.tables.users import Users, UserType
from security.api import Api, ApiError, ApiPermissionError, ApiRangeError
from security.session import Session

valid_key: Api = MagicMock(spec=Api)
valid_key.valid = True

valid_key.permissions = ["modify", "register", "list"]
valid_key.affected_domains = ["test[dot]eepy[dot]page", "affected[dot]eepy[dot]page"]

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

        with pytest.raises(PermissionError):
            Api.create(
                test_user["_id"],
                users,
                "test key",
                ["register"],
                domains=["domain-that-isnt-owned.eepy.page"],
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
