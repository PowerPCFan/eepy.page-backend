#!/usr/bin/env python3

"""Grant one user all known account permissions and unrestricted domain limits."""

from __future__ import annotations

import os
import pathlib
import sys
from pymongo import MongoClient

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from database.tables.users import Users  # pyright: ignore[reportMissingImports]  # noqa: E402
from simple_python_dotenv import load_dotenv  # noqa: E402

load_dotenv(backend_dir / ".env")

CONFIRMATION = "GRANT FULL ADMIN ACCESS"
UNRESTRICTED_LIMIT = 2**31 - 1
ADMIN_PERMISSIONS = {
    "account": True,
    "dns": True,
    "manage-permissions": True,
    "reports": True,
    "userdetails": True,
    "wildcards": True,
}


def get_user_id() -> str:
    user_id = os.getenv("USERID", "").strip()
    if not user_id:
        raise ValueError("USERID must be set to the target user's database ID")
    return user_id


def build_admin() -> dict[str, object]:
    return {"enabled": True, "permissions": dict(ADMIN_PERMISSIONS)}


def build_limits() -> dict[str, int]:
    return {"max-domains": UNRESTRICTED_LIMIT, "max-subdomains": UNRESTRICTED_LIMIT}


def build_features() -> dict[str, bool]:
    return {"invite": True}


def main() -> int:
    try:
        user_id = get_user_id()
    except ValueError as error:
        print(f"Error: {error}")
        return 2

    mongodb_url = os.getenv("MONGODB_URL", "").strip()
    if not mongodb_url:
        print("Error: MONGODB_URL is not set")
        return 2

    with MongoClient(mongodb_url) as client:
        users = Users(client)
        user = users.find_user({"_id": user_id}, find_banned=True)
        if user is None:
            print(f"No user found with ID: {user_id}")
            return 1

        new_admin = build_admin()
        new_limits = build_limits()
        new_features = build_features()

        print("DANGER: this will grant permanent owner-level access to:")
        print(f"  USERID: {user_id}")
        print(f"  Admin permissions: {', '.join(sorted(ADMIN_PERMISSIONS))}")
        print(f"  Domain limits: {UNRESTRICTED_LIMIT:,}")
        print("This changes the production user record and cannot be automatically undone.")
        try:
            confirmation = input(f'Type "{CONFIRMATION}" to continue: ').strip()
        except (EOFError, KeyboardInterrupt):
            print("Confirmation was interrupted. No changes were made.")
            return 1
        if confirmation != CONFIRMATION:
            print("Confirmation did not match. No changes were made.")
            return 1

        result = users.table.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "permissions.admin": new_admin,
                    "permissions.limits": new_limits,
                    "permissions.features": new_features,
                },
            },
        )

    if result.matched_count != 1:
        print("The user was found, but the permission update did not match.")
        return 1

    if result.modified_count == 0:
        print(f"{user_id} already had full admin access. No changes were needed.")
    else:
        print(f"Full admin access granted to {user_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
