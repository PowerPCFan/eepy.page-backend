#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

import requests
from sqlmodel import select

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.session import create_db_engine, session_scope
    from src.database.tables.domains import Domains
    from src.dns_.dns import sanitize
    from src.dns_.types import ALLOWED_TYPES
    from src.models.tables import Domain
else:
    from database.session import create_db_engine, session_scope
    from database.tables.domains import Domains
    from dns_.dns import sanitize
    from dns_.types import ALLOWED_TYPES
    from models.tables import Domain

load_dotenv(backend_dir / ".env")

TLDS = {"eepy.page", "worksonmymachine.top"}
EXCLUDED_NAMES = {
    item if any(item.endswith(tld) for tld in TLDS) else f"{item}.eepy.page"
    for item in str(os.getenv("EXCLUDED", "")).split(";")
    if item
}
RecordKey = tuple[str, str]


def normalized_values(values: object, record_type: str) -> tuple[str, ...]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable) or isinstance(values, (bytes, Mapping)):
        return ()
    return tuple(sorted(sanitize(value, record_type) for value in values if isinstance(value, str)))


def db_records(postgres_url: str) -> tuple[dict[RecordKey, list[tuple[str, ...]]], dict[RecordKey, set[str]]]:
    records: dict[RecordKey, list[tuple[str, ...]]] = defaultdict(list)
    owners: dict[RecordKey, set[str]] = defaultdict(set)

    engine = create_db_engine(postgres_url)
    with session_scope(engine) as session:
        for dom in session.exec(select(Domain)).all():
            record_type = dom.type.upper()
            if record_type not in ALLOWED_TYPES:
                continue
            key = (Domains.canonical_full_domain_name(dom.name), record_type)
            records[key].append(normalized_values(dom.ip, record_type))
            owners[key].add(dom.user_id)

    return records, owners


def powerdns_records(
    session: requests.Session,
    powerdns_url: str,
    api_key: str,
) -> dict[RecordKey, list[tuple[str, ...]]]:
    headers = {"X-API-Key": api_key}
    server_url = f"{powerdns_url}/api/v1/servers/localhost"

    zones_response = session.get(f"{server_url}/zones", headers=headers, timeout=10)
    zones_response.raise_for_status()

    records: dict[RecordKey, list[tuple[str, ...]]] = defaultdict(list)
    for zone in zones_response.json():
        zone_name = zone.get("name")
        if not isinstance(zone_name, str):
            continue

        zone_response = session.get(f"{server_url}/zones/{zone_name}", headers=headers, timeout=10)
        zone_response.raise_for_status()

        for rrset in zone_response.json().get("rrsets", []):
            name = rrset.get("name")
            record_type = rrset.get("type")
            if not isinstance(name, str) or not isinstance(record_type, str):
                continue
            record_type = record_type.upper()
            if record_type not in ALLOWED_TYPES:
                continue

            canonical_name = name.rstrip(".").lower()
            if canonical_name in EXCLUDED_NAMES:
                continue

            values = [
                record["content"]
                for record in rrset.get("records", [])
                if isinstance(record, Mapping) and isinstance(record.get("content"), str)
            ]
            records[(canonical_name, record_type)].append(normalized_values(values, record_type))

    return records


def describe(key: RecordKey) -> str:
    return f"{key[0]} [{key[1]}]"


def print_section(title: str, items: list[str]) -> int:
    if not items:
        return 0
    print(f"\n== {title} ({len(items)}) ==")
    for item in items:
        print(f"- {item}")
    return len(items)


def main() -> int:
    postgres_url = os.getenv("POSTGRES_URL", "").strip()
    powerdns_url = os.getenv("PDNS_DOMAIN", "").rstrip("/")
    api_key = os.getenv("PDNS_API_KEY", "")

    if not postgres_url or not powerdns_url or not api_key:
        print("POSTGRES_URL, PDNS_DOMAIN, and PDNS_API_KEY must be set", file=sys.stderr)
        return 1

    with requests.Session() as session:
        pg_recs, owners = db_records(postgres_url)
        pdns = powerdns_records(session, powerdns_url, api_key)

    pg_keys = set(pg_recs)
    pdns_keys = set(pdns)
    issues = 0

    duplicate_db = [
        f"{describe(key)} appears {len(values)} times for users {', '.join(sorted(owners[key]))}"
        for key, values in pg_recs.items()
        if len(values) > 1
    ]
    issues += print_section("Duplicate PostgreSQL records", duplicate_db)

    missing_from_pdns = [describe(key) for key in sorted(pg_keys - pdns_keys)]
    issues += print_section("PostgreSQL records missing from PowerDNS", missing_from_pdns)

    missing_from_db = [describe(key) for key in sorted(pdns_keys - pg_keys)]
    issues += print_section("PowerDNS records missing from PostgreSQL", missing_from_db)

    mismatches = []
    for key in sorted(pg_keys & pdns_keys):
        db_values = set(pg_recs[key])
        pdns_values = set(pdns[key])
        if len(db_values) != 1 or len(pdns_values) != 1 or next(iter(db_values)) != next(iter(pdns_values)):
            mismatches.append(f"{describe(key)}: Postgres={sorted(db_values)} PowerDNS={sorted(pdns_values)}")
    issues += print_section("Record value mismatches", mismatches)

    print(
        f"\nChecked {len(pg_keys)} PostgreSQL keys and {len(pdns_keys)} PowerDNS keys; found {issues} issue(s).",
        file=sys.stderr,
    )
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
