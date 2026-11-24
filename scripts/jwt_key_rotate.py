#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from typing import TYPE_CHECKING

from sqlalchemy import func
from sqlmodel import delete, select

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
dotenv = backend_dir / ".env"

sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.session import create_db_engine, session_scope
    from src.models.tables import SessionModel
else:
    from database.session import create_db_engine, session_scope
    from models.tables import SessionModel

load_dotenv(dotenv)


def main() -> int:
    postgres_url = os.getenv("POSTGRES_URL", "")
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")

    engine = create_db_engine(postgres_url)
    with session_scope(engine) as session:
        session_count = int(session.exec(select(func.count()).select_from(SessionModel)).one() or 0)
        if not apply:
            print(f"[dry run] Would delete {session_count} session row(s)")
            return 0
        result = session.exec(delete(SessionModel))
        deleted = int(result.rowcount or 0)  # pyright: ignore[reportAttributeAccessIssue]

    print(f"Deleted {deleted} session row(s)")
    print("JWT_KEY migration complete - existing sessions were removed from PostgreSQL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
