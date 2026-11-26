from typing import TYPE_CHECKING

import pytest

from database.models import ApiKey, Domain, User, UserRiskProfile
from database.tables.users import Users
from security.api import Api, ApiError, ApiKeyLimitError, ApiPermissionError, ApiRangeError
from security.encryption import Encryption
from security.session import Session

if TYPE_CHECKING:
    from tests.conftest import TestUserFactory


@pytest.fixture
def valid_api_key(users: Users, encryption: Encryption, insert_test_user: "TestUserFactory") -> Api:
    user_id = Encryption.sha256("api_decorator_test_user")
    insert_test_user(
        id=user_id,
        email=encryption.encrypt("api_decorator@example.com"),
        email_hash=encryption.hash_email("api_decorator@example.com"),
        normalized_email_hash=encryption.hash_email("api_decorator@example.com"),
        display_name=encryption.encrypt("api_decorator_test_user"),
        username=user_id,
        verified=True,
        domains=[
            Domain(user_id=user_id, name="test.eepy.page", type="A", ip=["1.2.3.4"], registered=1700000000),
            Domain(user_id=user_id, name="affected.eepy.page", type="A", ip=["1.2.3.4"], registered=1700000000),
        ],
    )
    raw_key = Api.create(
        user_id,
        users,
        "decorator test key",
        ["modify", "register", "list"],
        domains=["test.eepy.page", "affected.eepy.page"],
    )
    return Api(raw_key, users)


@pytest.fixture
def invalid_api_key(users: Users) -> Api:
    return Api("$APIV2=00000000000000000000000000000000", users)


@pytest.mark.order(-1)
class TestUserApi:
    def test_creation(self, test_session: Session, users: Users, test_user: User) -> None:
        Api.create(
            test_user.id,
            users,
            "test key",
            ["register", "modify"],
            domains=["test.eepy.page"],
        )

        with pytest.raises(ApiKeyLimitError):
            Api.create(
                test_user.id,
                users,
                "second key",
                ["register"],
                domains=["test.eepy.page"],
            )

        with pytest.raises(PermissionError):
            Api.create(
                test_user.id,
                users,
                "test key",
                ["register"],
                domains=["domain-that-isnt-owned.eepy.page"],
            )

        users.clear_api_keys(test_user.id)

    def test_key_permissions(self, test_user: User, users: Users) -> None:
        key = Api.create(
            test_user.id,
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


def test_requires_auth_valid_key(valid_api_key: Api) -> None:
    @Api.requires_auth
    def protected(api: Api) -> str:
        return "Executed"

    assert protected(api=valid_api_key) == "Executed"


def test_requires_auth_invalid_key(invalid_api_key: Api) -> None:
    @Api.requires_auth
    def protected(api: Api) -> str:
        return "Executed"

    with pytest.raises(ApiError):
        protected(api=invalid_api_key)


def test_requires_perms_valid(valid_api_key: Api) -> None:
    @Api.requires_auth
    @Api.requires_permission("register")
    def protected(api: Api) -> str:
        return "Executed"

    assert protected(api=valid_api_key) == "Executed"


def test_requires_perms_invalid(valid_api_key: Api) -> None:
    @Api.requires_auth
    @Api.requires_permission("delete")
    def protected(api: Api) -> str:
        return "Executed"

    with pytest.raises(ApiPermissionError):
        protected(api=valid_api_key)


def test_modification_domain(valid_api_key: Api) -> None:
    @Api.requires_auth
    @Api.requires_permission("modify")
    def protected(api: Api, domain: str) -> str:
        return "Executed"

    assert protected(api=valid_api_key, domain="affected.eepy.page") == "Executed"


def test_invalid_modification_domain(valid_api_key: Api) -> None:
    @Api.requires_auth
    @Api.requires_permission("modify")
    def protected(api: Api, domain: str) -> str:
        return "Executed"

    with pytest.raises(ApiRangeError):
        protected(api=valid_api_key, domain="unaffected.eepy.page")


def test_disabled_account_rejected_on_api_key(
    users: Users,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> None:
    raw_api_key = "$APIV2=0123456789abcdef0123456789abcdef"
    key_hash = Encryption.sha256(raw_api_key + "eepy.page")
    user_id = Encryption.sha256("disabled_api_user")

    insert_test_user(
        id=user_id,
        email=encryption.encrypt("u@example.com"),
        email_hash=encryption.hash_email("u@example.com"),
        normalized_email_hash=encryption.hash_email("u@example.com"),
        display_name=encryption.encrypt("disabled_api_user"),
        username=user_id,
        country={"country": "US"},
        created=1700000000,
        last_login=1700000000,
        verified=True,
        domains=[Domain(user_id=user_id, name="sub.eepy.page", type="A", ip=["1.2.3.4"], registered=1700000000)],
        api_keys=[
            ApiKey(
                id=key_hash,
                user_id=user_id,
                string=encryption.encrypt(raw_api_key),
                perms=["modify", "register", "delete", "list"],
                domains=["*"],
                comment="key",
            ),
        ],
        risk_profile=UserRiskProfile(
            user_id=user_id,
            score=85,
            disabled=True,
            disable_reasons=["Auto-disabled"],
        ),
    )

    api = Api(raw_api_key, users)
    assert api.valid is False

    @Api.requires_auth
    def protected_api_call(api: Api) -> str:
        return "ok"

    with pytest.raises(ApiError):
        protected_api_call(api=api)

