#!/usr/bin/env python3

"""Grant one user all known account permissions and unrestricted domain limits."""

from __future__ import annotations

import os
import pathlib
import sys
from typing import TYPE_CHECKING

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.session import create_db_engine
    from src.database.tables.users import Users
else:
    from database.session import create_db_engine
    from database.tables.users import Users

load_dotenv(backend_dir / ".env")

CONFIRMATION = "GRANT FULL ADMIN ACCESS"
UNRESTRICTED_LIMIT = 2**31 - 1
ADMIN_PERMISSIONS = {
    "account": True,
    "dns": True,
    "manage_permissions": True,
    "reports": True,
    "userdetails": True,
    "wildcards": True,
}


def get_user_id() -> str:
    user_id = os.getenv("USERID", "").strip()
    if not user_id:
        msg = "USERID must be set to the target user's database ID"
        raise ValueError(msg)
    return user_id


def main() -> int:
    try:
        user_id = get_user_id()
    except ValueError as error:
        print(f"Error: {error}")
        return 2

    postgres_url = os.getenv("POSTGRES_URL", "").strip()
    if not postgres_url:
        print("Error: POSTGRES_URL is not set")
        return 2

    engine = create_db_engine(postgres_url)
    users = Users(engine)
    user = users.get_user(user_id, find_banned=True)
    if user is None:
        print(f"No user found with ID: {user_id}")
        return 1

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

    users.grant_full_admin(user_id, UNRESTRICTED_LIMIT)
    print(f"Full admin access granted to {user_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
