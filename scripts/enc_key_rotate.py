#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import select

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
dotenv = backend_dir / ".env"

sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from sqlmodel import Session

    from src.database.session import create_db_engine, session_scope
    from src.models.tables import Reward, User, VerificationCode
else:
    from database.session import create_db_engine, session_scope
    from models.tables import Reward, User, VerificationCode

load_dotenv(dotenv)


@dataclass
class RotationStats:
    documents_seen: int = 0
    documents_changed: int = 0
    values_rotated: int = 0
    errors: int = 0


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
    session: Session,
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    apply: bool,
) -> RotationStats:
    stats = RotationStats()

    for user in session.exec(select(User)).all():
        stats.documents_seen += 1
        user_id = user.id
        changed = False

        try:
            rotated_email = rotate_value(user.email, decrypt_old, encrypt_new, path=f"users.{user_id}.email")
            if rotated_email is not None:
                if apply:
                    user.email = rotated_email
                changed = True
                stats.values_rotated += 1
        except ValueError as exc:
            stats.errors += 1
            print(exc, file=sys.stderr)

        try:
            rotated_dn = rotate_value(user.display_name, decrypt_old, encrypt_new, path=f"users.{user_id}.display_name")
            if rotated_dn is not None:
                if apply:
                    user.display_name = rotated_dn
                changed = True
                stats.values_rotated += 1
        except ValueError as exc:
            stats.errors += 1
            print(exc, file=sys.stderr)

        mfa = user.mfa
        mfa_changed = False
        if mfa is not None:
            if mfa.secret_key:
                try:
                    rotated_key = rotate_value(
                        mfa.secret_key,
                        decrypt_old,
                        encrypt_new,
                        path=f"user_mfa.{user_id}.secret_key",
                    )
                    if rotated_key is not None:
                        if apply:
                            mfa.secret_key = rotated_key
                        mfa_changed = True
                        changed = True
                        stats.values_rotated += 1
                except ValueError as exc:
                    stats.errors += 1
                    print(exc, file=sys.stderr)

            recovery_codes = list(mfa.recovery_codes or [])
            rotated_codes: list[str] = []
            for index, code in enumerate(recovery_codes):
                try:
                    rotated = rotate_value(
                        code,
                        decrypt_old,
                        encrypt_new,
                        path=f"user_mfa.{user_id}.recovery_codes.{index}",
                    )
                    if rotated is not None:
                        rotated_codes.append(rotated)
                        mfa_changed = True
                        changed = True
                        stats.values_rotated += 1
                    else:
                        rotated_codes.append(code)
                except ValueError as exc:
                    stats.errors += 1
                    print(exc, file=sys.stderr)
                    rotated_codes.append(code)
            if mfa_changed and apply:
                mfa.recovery_codes = rotated_codes
                flag_modified(mfa, "recovery_codes")
                session.add(mfa)

        for ak in user.api_keys or []:
            try:
                rotated_ak = rotate_value(ak.string, decrypt_old, encrypt_new, path=f"api_keys.{ak.id}.string")
                if rotated_ak is not None:
                    if apply:
                        ak.string = rotated_ak
                        session.add(ak)
                    changed = True
                    stats.values_rotated += 1
            except ValueError as exc:
                stats.errors += 1
                print(exc, file=sys.stderr)

        if changed:
            stats.documents_changed += 1
            if apply:
                session.add(user)

    return stats


def rotate_codes(
    session: Session,
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    apply: bool,
) -> RotationStats:
    stats = RotationStats()
    for code_row in session.exec(select(VerificationCode)).all():
        stats.documents_seen += 1
        try:
            rotated = rotate_value(code_row.account, decrypt_old, encrypt_new, path=f"codes.{code_row.id}.account")
        except ValueError as exc:
            stats.errors += 1
            print(exc, file=sys.stderr)
            continue
        if rotated is not None:
            stats.values_rotated += 1
            stats.documents_changed += 1
            if apply:
                code_row.account = rotated
                session.add(code_row)
    return stats


def rotate_rewards(
    session: Session,
    decrypt_old: Callable[[bytes], bytes],
    encrypt_new: Callable[[bytes], bytes],
    *,
    apply: bool,
) -> RotationStats:
    stats = RotationStats()
    for reward_row in session.exec(select(Reward)).all():
        stats.documents_seen += 1
        try:
            rotated = rotate_value(
                reward_row.associated_email,
                decrypt_old,
                encrypt_new,
                path=f"rewards.{reward_row.id}.associated_email",
            )
        except ValueError as exc:
            stats.errors += 1
            print(exc, file=sys.stderr)
            continue
        if rotated is not None:
            stats.values_rotated += 1
            stats.documents_changed += 1
            if apply:
                reward_row.associated_email = rotated
                session.add(reward_row)
    return stats


def print_stats(label: str, stats: RotationStats) -> None:
    print(
        f"{label}: seen={stats.documents_seen}, changed={stats.documents_changed}, "
        f"values_rotated={stats.values_rotated}, errors={stats.errors}",
    )


def main() -> int:
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")
    postgres_url = str(os.getenv("POSTGRES_URL", "")).strip()

    old_fernet = Fernet(str(os.getenv("ENC_KEY", "")).strip().encode("utf-8"))
    new_fernet_plaintext = Fernet.generate_key().decode()
    new_fernet = Fernet(new_fernet_plaintext.encode("utf-8"))

    if not apply:
        print("Dry run only. Re-run with apply to write rotated values.")

    engine = create_db_engine(postgres_url)
    with session_scope(engine) as session:
        user_stats = rotate_users(session, old_fernet.decrypt, new_fernet.encrypt, apply=apply)
        code_stats = rotate_codes(session, old_fernet.decrypt, new_fernet.encrypt, apply=apply)
        reward_stats = rotate_rewards(session, old_fernet.decrypt, new_fernet.encrypt, apply=apply)

    print_stats("users", user_stats)
    print_stats("codes", code_stats)
    print_stats("rewards", reward_stats)

    total_errors = user_stats.errors + code_stats.errors + reward_stats.errors
    if total_errors:
        print(f"Finished with {total_errors} error(s).", file=sys.stderr)
        return 1

    print("Rotation complete. Paste this value into your .env to complete migration:")
    print(f"ENC_KEY={new_fernet_plaintext}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
