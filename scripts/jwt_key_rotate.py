#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select

from src.database.session import rowcount

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
dotenv = backend_dir / ".env"

sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.models import SessionModel
    from src.database.session import create_db_engine, rowcount, session_scope
else:
    from database.models import SessionModel
    from database.session import create_db_engine, rowcount, session_scope

load_dotenv(dotenv)


def main() -> int:
    postgres_url = os.getenv("POSTGRES_URL", "")
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")

    engine = create_db_engine(postgres_url)
    with session_scope(engine) as session:
        session_count = int(session.scalar(select(func.count()).select_from(SessionModel)) or 0)
        if not apply:
            print(f"[dry run] Would delete {session_count} session row(s)")
            return 0
        result = session.execute(delete(SessionModel))
        deleted = rowcount(result)

    print(f"Deleted {deleted} session row(s)")
    print("JWT_KEY migration complete - existing sessions were removed from PostgreSQL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
