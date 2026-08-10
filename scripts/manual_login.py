#!/usr/bin/env python3

"""
A script to manually log into accounts
Used for local testing/dev and account recovery
"""

from __future__ import annotations
import os
import json
import jwt
from typing import TYPE_CHECKING
from pymongo import MongoClient


if TYPE_CHECKING:
    # these imports dont work at runtime but the type checker
    # thinks they do so it provides proper type checking/hints
    from src.database.tables.sessions import Sessions
    from src.database.tables.users import Users
    from src.security.session import Session
else:
    # all the janky runtime stuff

    import pathlib
    scripts_dir = pathlib.Path(__file__).resolve().parent
    backend_dir = scripts_dir.parent

    import sys
    sys.path.insert(0, str(backend_dir / "src"))
    sys.path.insert(0, str(scripts_dir))

    from database.tables.sessions import Sessions
    from database.tables.users import Users
    from security.session import Session

    from simple_python_dotenv import load_dotenv
    load_dotenv(backend_dir / ".env")


def get_token_id(token: str) -> str:
    return str(jwt.decode(token, options={"verify_signature": False})["jti"])


def remove_metadata(*, users: Users, user_id: str, original: dict) -> None:
    print(f"removing metadata for user {user_id}")
    
    fields_to_restore = ("accessed-from", "last-login")
    restore = {}
    unset = {}

    for field in fields_to_restore:
        if field in original:
            restore[field] = original[field]
        else:
            unset[field] = ""

    update = {}

    if restore:
        update["$set"] = restore
    if unset:
        update["$unset"] = unset
    if update:
        users.table.update_one(
            filter={"_id": user_id},
            update=update,
        )

    print("metadata removed.")
    print(f"restored: {update}")
    print(f"unset: {unset}")


def main() -> int:
    user_id = str(os.getenv("USERID", "")).strip()
    mongo_url = str(os.getenv("MONGODB_URL", "")).strip()

    with MongoClient(mongo_url) as client:
        users = Users(client)
        sessions = Sessions(client)
        user_doc = users.table.find_one(
            {"_id": user_id},
            {"accessed-from": 1, "last-login": 1},
        )
        user_obj = users.find_user({"_id": user_id})

        if not (user_doc and user_obj):
            print(f"no user with id {user_id}")
            return 1

        session = Session.create(
            username=user_id,
            real_username=None,
            mfa_code=None,
            ip="127.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
            users=users,
            session_table=sessions,
            skip_mfa=True,
        )

        access_token = session.get("access_token")
        refresh_token = session.get("refresh_token")

        if not session.get("success", False) or not (access_token and refresh_token):
            print("failed to create session")
            return 1

        print(f"""\
paste this snippet into the devtools console on eepy.page:


document.cookie = '__Host-auth-token=' + encodeURIComponent(
    {json.dumps(access_token)}
) + '; Path=/; Secure; SameSite=Strict';
document.cookie = 'logged-in=yes; Path=/';
localStorage.setItem('logged-in', 'y');
location.reload();


token expiry info:
- access token: 10 mins
- refresh token: 14 days

press enter to terminate session...
        """, flush=True)

        try:
            input()
        finally:
            print("terminating session...")
            sessions.delete_many(
                {"_id": {"$in": [get_token_id(access_token), get_token_id(refresh_token)]}}
            )
            print("removed access_token and refresh_token")

            remove_metadata(
                users=users,
                user_id=user_id,
                original=user_doc,
            )

            print("success: session fully terminated and removed from DB")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
