#!/usr/bin/env python3

"""
A script to manually log into accounts
Used for local testing/dev and account recovery
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import TYPE_CHECKING

import jwt

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.session import create_db_engine
    from src.database.tables.sessions import Sessions
    from src.database.tables.users import Users
    from src.security.session import Session
else:
    from database.session import create_db_engine
    from database.tables.sessions import Sessions
    from database.tables.users import Users
    from security.session import Session

load_dotenv(backend_dir / ".env")


def get_token_id(token: str) -> str:
    return str(jwt.decode(token, options={"verify_signature": False})["jti"])


def main() -> int:
    user_id = str(os.getenv("USERID", "")).strip()
    postgres_url = str(os.getenv("POSTGRES_URL", "")).strip()

    engine = create_db_engine(postgres_url)
    users = Users(engine)
    sessions = Sessions(engine)

    user_obj = users.get_user(user_id)
    if not user_obj:
        print(f"no user with id {user_id}")
        return 1

    original_metadata = {
        "accessed_from": [
            {"ip": row.ip, "first_seen": row.first_seen, "last_seen": row.last_seen}
            for row in (user_obj.ips or [])
        ],
        "last_login": user_obj.last_login,
    }

    session = Session.create(
        username=user_id,
        real_username=None,
        mfa_code=None,
        ip="127.0.0.1",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
        ),
        users=users,
        session_table=sessions,
        skip_mfa=True,
    )

    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    if not session.get("success", False) or not (access_token and refresh_token):
        print("failed to create session")
        return 1

    print(
        f"""\
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
        """,
        flush=True,
    )

    try:
        input()
    finally:
        print("terminating session...")
        sessions.delete_by_id(get_token_id(access_token))
        sessions.delete_by_id(get_token_id(refresh_token))
        print("removed access_token and refresh_token")

        users.restore_login_metadata(user_id, original_metadata)
        print("success: session fully terminated and removed from DB")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
