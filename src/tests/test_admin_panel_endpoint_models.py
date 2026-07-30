import pytest

from server.routes.models.admin import AdminPermissionChange, BanUser, IpFind


def test_admin_permission_change_accepts_numeric_limits() -> None:
    model = AdminPermissionChange.model_validate(
        {
            "id": "user123",
            "permission": "max-domains",
            "value": "5",
            "send_email": False,
        },
    )

    assert model.value == 5
    assert isinstance(model.value, int)


def test_admin_permission_change_rejects_non_numeric_limits() -> None:
    with pytest.raises(ValueError, match="Permission value must be an integer"):
        AdminPermissionChange.model_validate(
            {
                "id": "user123",
                "permission": "max-domains",
                "value": "abc",
                "send_email": False,
            },
        )


def test_admin_permission_change_accepts_boolean_strings() -> None:
    model = AdminPermissionChange.model_validate(
        {
            "id": "user123",
            "permission": "enabled",
            "value": "true",
            "send_email": False,
        },
    )

    assert model.value is True
    assert isinstance(model.value, bool)


def test_admin_permission_change_rejects_invalid_boolean_strings() -> None:
    with pytest.raises(ValueError, match="Permission value must be a boolean"):
        AdminPermissionChange.model_validate(
            {
                "id": "user123",
                "permission": "account",
                "value": "maybe",
                "send_email": False,
            },
        )


def test_admin_permission_change_rejects_invalid_permission_name() -> None:
    with pytest.raises(ValueError, match="Invalid permission"):
        AdminPermissionChange.model_validate(
            {
                "id": "user123",
                "permission": "not-a-perm",
                "value": "true",
                "send_email": False,
            },
        )


def test_ban_user_rejects_empty_reasons_list() -> None:
    with pytest.raises(ValueError, match="At least one ban reason is required"):
        BanUser.model_validate(
            {"user_id": "user123", "reasons": [], "send_email": False},
        )


def test_ip_find_rejects_empty_ips() -> None:
    with pytest.raises(ValueError, match="At least one IP address is required"):
        IpFind.model_validate({"ips": []})
