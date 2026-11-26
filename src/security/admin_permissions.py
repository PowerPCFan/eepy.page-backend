from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from database.models import User

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


def admin_is_enabled(user: User | None) -> bool:
    return bool(user is not None and user.permissions_rel is not None and user.permissions_rel.admin_enabled)


def has_admin_permission(user: User | None, permission: str) -> bool:
    if not admin_is_enabled(user) or permission not in ADMIN_PERMISSION_NAMES:
        return False
    assert user is not None
    assert user.permissions_rel is not None
    return bool(getattr(user.permissions_rel, f"admin_{permission}", False))


def get_admin_permissions(user: User | None) -> list[str]:
    if not admin_is_enabled(user):
        return []
    assert user is not None
    assert user.permissions_rel is not None
    perms = user.permissions_rel
    return [name for name in ADMIN_PERMISSION_NAMES if getattr(perms, f"admin_{name}", False)]


def get_feature_permissions(user: User | None) -> list[str]:
    if user is None or user.permissions_rel is None:
        return []
    return ["invite"] if user.permissions_rel.feature_invite else []


def get_account_limits(user: User | None) -> dict[str, int]:
    if user is None or user.permissions_rel is None:
        return {"max_domains": 3, "max_subdomains": 5}
    return {
        "max_domains": user.permissions_rel.max_domains,
        "max_subdomains": user.permissions_rel.max_subdomains,
    }
