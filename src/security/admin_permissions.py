from __future__ import annotations

from typing import Any

ADMIN_PERMISSION_NAMES = frozenset(
    {
        "account",
        "dns",
        "manage-permissions",
        "reports",
        "userdetails",
        "wildcards",
    },
)
FEATURE_NAMES = frozenset({"invite"})


def admin_is_enabled(user: dict[str, Any]) -> bool:
    permissions = user.get("permissions")
    admin = permissions.get("admin") if isinstance(permissions, dict) else None
    return isinstance(admin, dict) and admin.get("enabled") is True


def has_admin_permission(user: dict[str, Any], permission: str) -> bool:
    if not admin_is_enabled(user):
        return False

    admin = user["permissions"]["admin"]
    permissions = admin.get("permissions")
    return (
        permission in ADMIN_PERMISSION_NAMES and isinstance(permissions, dict) and permissions.get(permission) is True
    )


def get_admin_permissions(user: dict[str, Any]) -> list[str]:
    if not admin_is_enabled(user):
        return []

    permissions = user["permissions"]["admin"].get("permissions")
    if not isinstance(permissions, dict):
        return []

    return [
        permission
        for permission in permissions
        if permission in ADMIN_PERMISSION_NAMES and permissions.get(permission) is True
    ]


def get_feature_permissions(user: dict[str, Any]) -> list[str]:
    permissions = user.get("permissions")
    features = permissions.get("features") if isinstance(permissions, dict) else None
    if not isinstance(features, dict):
        return []

    return [feature for feature in features if feature in FEATURE_NAMES and features.get(feature) is True]


def get_account_limits(user: dict[str, Any]) -> dict[str, int]:
    permissions = user.get("permissions")
    limits = permissions.get("limits") if isinstance(permissions, dict) else None
    if not isinstance(limits, dict):
        return {"max-domains": 3, "max-subdomains": 5}

    return {
        "max-domains": limits.get("max-domains", 3),
        "max-subdomains": limits.get("max-subdomains", 5),
    }
