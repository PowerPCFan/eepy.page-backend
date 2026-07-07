#!/usr/bin/env python3

from __future__ import annotations
import os
import sys
import pathlib
from pymongo import MongoClient

scripts_dir = pathlib.Path(__file__).resolve().parent
dotenv = scripts_dir.parent / ".env"

sys.path.insert(0, str(scripts_dir))
# could just use python-dotenv since its in the same venv as pymongo
# but i was bored and made this so i might as well put it to use somewhere
from simple_python_dotenv import load_dotenv
load_dotenv(dotenv)

def main() -> int:
    mongodb_url = os.getenv("MONGODB_URL", "")
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")

    with MongoClient(mongodb_url) as cli:
        collection = cli["database"]["sessions"]
        session_count = collection.count_documents({})
        if not apply:
            print(f"[dry run] Would delete {session_count} session document(s)")
            return 0
        result = collection.delete_many({})

    print(f"Deleted {result.deleted_count} session document(s)")
    print("JWT_KEY migration complete - existing sessions were removed from MongoDB.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
