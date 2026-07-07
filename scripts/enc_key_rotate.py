#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet, InvalidToken
from pymongo import MongoClient

if TYPE_CHECKING:
    from collections.abc import Callable


DATABASE_NAME = "database"
USERS_COLLECTION = "eepy.page"
CODES_COLLECTION = "codes"
REWARDS_COLLECTION = "rewards"


@dataclass
class RotationStats:
    documents_seen: int = 0
    documents_changed: int = 0
    values_rotated: int = 0
    errors: int = 0


def env_or_arg(value: str | None, env_name: str) -> str:
    resolved = value or os.getenv(env_name)
    if not resolved:
        print(f"Missing required value: pass --{env_name.lower().replace('_', '-')} or set {env_name}", file=sys.stderr)
        sys.exit(2)
    return resolved


def rotate_value(
    value: object,
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    path: str,
) -> str | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        plaintext = decrypt_old(value.encode("utf-8"))
    except InvalidToken as exc:
        msg = f"Could not decrypt {path}; old key is wrong or value is not a Fernet token"
        raise ValueError(msg) from exc

    return encrypt_new(plaintext).decode("utf-8")


def rotate_users(  # noqa: C901, PLR0912, PLR0915
    db: Any,  # noqa: ANN401
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    apply: bool,
) -> RotationStats:
    stats = RotationStats()
    collection = db[USERS_COLLECTION]

    for user in collection.find({}):
        stats.documents_seen += 1
        user_id = user.get("_id")
        updates: dict[str, object] = {}

        fields = {
            "email": user.get("email"),
            "display-name": user.get("display-name"),
            "totp.key": user.get("totp", {}).get("key") if isinstance(user.get("totp"), dict) else None,
        }

        for path, value in fields.items():
            try:
                rotated = rotate_value(value, decrypt_old, encrypt_new, path=f"{USERS_COLLECTION}.{user_id}.{path}")
            except ValueError as exc:
                stats.errors += 1
                print(exc, file=sys.stderr)
                continue

            if rotated is not None:
                updates[path] = rotated
                stats.values_rotated += 1

        api_keys = user.get("api-keys", {})
        if isinstance(api_keys, dict):
            for api_key_hash, api_key in api_keys.items():
                if not isinstance(api_key, dict):
                    continue

                path = f"api-keys.{api_key_hash}.string"
                try:
                    rotated = rotate_value(
                        api_key.get("string"),
                        decrypt_old,
                        encrypt_new,
                        path=f"{USERS_COLLECTION}.{user_id}.{path}",
                    )
                except ValueError as exc:
                    stats.errors += 1
                    print(exc, file=sys.stderr)
                    continue

                if rotated is not None:
                    updates[path] = rotated
                    stats.values_rotated += 1

        totp = user.get("totp", {})
        recovery_codes = totp.get("recovery", []) if isinstance(totp, dict) else []
        if isinstance(recovery_codes, list):
            rotated_codes: list[object] = []
            changed = False
            for index, code in enumerate(recovery_codes):
                try:
                    rotated = rotate_value(
                        code,
                        decrypt_old,
                        encrypt_new,
                        path=f"{USERS_COLLECTION}.{user_id}.totp.recovery.{index}",
                    )
                except ValueError as exc:
                    stats.errors += 1
                    print(exc, file=sys.stderr)
                    rotated_codes.append(code)
                    continue

                if rotated is None:
                    rotated_codes.append(code)
                else:
                    rotated_codes.append(rotated)
                    changed = True
                    stats.values_rotated += 1

            if changed:
                updates["totp.recovery"] = rotated_codes

        if updates:
            stats.documents_changed += 1
            if apply:
                collection.update_one({"_id": user_id}, {"$set": updates})

    return stats


def rotate_simple_collection(  # noqa: PLR0913
    db: Any,  # noqa: ANN401
    collection_name: str,
    field_name: str,
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    apply: bool,
) -> RotationStats:
    stats = RotationStats()
    collection = db[collection_name]

    for document in collection.find({field_name: {"$exists": True}}):
        stats.documents_seen += 1
        document_id = document.get("_id")
        try:
            rotated = rotate_value(
                document.get(field_name),
                decrypt_old,
                encrypt_new,
                path=f"{collection_name}.{document_id}.{field_name}",
            )
        except ValueError as exc:
            stats.errors += 1
            print(exc, file=sys.stderr)
            continue

        if rotated is None:
            continue

        stats.values_rotated += 1
        stats.documents_changed += 1
        if apply:
            collection.update_one({"_id": document_id}, {"$set": {field_name: rotated}})

    return stats


def print_stats(label: str, stats: RotationStats) -> None:
    print(
        f"{label}: seen={stats.documents_seen}, changed={stats.documents_changed}, "
        f"values_rotated={stats.values_rotated}, errors={stats.errors}",
    )


def main() -> int:
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")
    mongodb_url = str(os.getenv("MONGODB_URL", "")).strip()

    old_fernet = Fernet(str(os.getenv("ENC_KEY", "")).strip().encode("utf-8"))
    new_fernet_plaintext = Fernet.generate_key().decode()
    new_fernet = Fernet(new_fernet_plaintext.encode("utf-8"))

    if not apply:
        print("Dry run only. Re-run with apply to write rotated values.")

    client = MongoClient(mongodb_url)
    db = client[DATABASE_NAME]

    try:
        user_stats = rotate_users(
            db,
            old_fernet.decrypt,
            new_fernet.encrypt,
            apply=apply,
        )
        code_stats = rotate_simple_collection(
            db,
            CODES_COLLECTION,
            "account",
            old_fernet.decrypt,
            new_fernet.encrypt,
            apply=apply,
        )
        reward_stats = rotate_simple_collection(
            db,
            REWARDS_COLLECTION,
            "associated-email",
            old_fernet.decrypt,
            new_fernet.encrypt,
            apply=apply,
        )
    finally:
        client.close()

    print_stats(USERS_COLLECTION, user_stats)
    print_stats(CODES_COLLECTION, code_stats)
    print_stats(REWARDS_COLLECTION, reward_stats)

    total_errors = user_stats.errors + code_stats.errors + reward_stats.errors
    if total_errors:
        print(f"Finished with {total_errors} error(s).", file=sys.stderr)
        return 1

    if apply:
        print("Rotation complete. Paste this value into your .env to complete migration:")
        print(f"ENC_KEY={new_fernet_plaintext}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
