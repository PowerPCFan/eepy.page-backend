from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ADMIN_PERMISSION_NAMES = frozenset(
    {
        "account",
        "dns",
        "manage_permissions",
        "reports",
        "userdetails",
        "wildcards",
    },
)
FEATURE_NAMES = frozenset({"invite"})


def admin_is_enabled(user: Mapping[str, Any]) -> bool:
    permissions = user.get("permissions")
    admin = permissions.get("admin") if isinstance(permissions, Mapping) else None
    return isinstance(admin, Mapping) and admin.get("enabled") is True


def has_admin_permission(user: Mapping[str, Any], permission: str) -> bool:
    if not admin_is_enabled(user):
        return False

    admin = user["permissions"]["admin"]
    permissions = admin.get("permissions")
    return (
        permission in ADMIN_PERMISSION_NAMES
        and isinstance(permissions, Mapping)
        and permissions.get(permission) is True
    )


def get_admin_permissions(user: Mapping[str, Any]) -> list[str]:
    if not admin_is_enabled(user):
        return []

    permissions = user["permissions"]["admin"].get("permissions")
    if not isinstance(permissions, Mapping):
        return []

    return [
        permission
        for permission in permissions
        if permission in ADMIN_PERMISSION_NAMES and permissions.get(permission) is True
    ]


def get_feature_permissions(user: Mapping[str, Any]) -> list[str]:
    permissions = user.get("permissions")
    features = permissions.get("features") if isinstance(permissions, Mapping) else None
    if not isinstance(features, Mapping):
        return []

    return [feature for feature in features if feature in FEATURE_NAMES and features.get(feature) is True]


def get_account_limits(user: Mapping[str, Any]) -> dict[str, int]:
    permissions = user.get("permissions")
    limits = permissions.get("limits") if isinstance(permissions, Mapping) else None
    if not isinstance(limits, Mapping):
        return {"max_domains": 3, "max_subdomains": 5}

    return {
        "max_domains": limits.get("max_domains", 3),
        "max_subdomains": limits.get("max_subdomains", 5),
    }
