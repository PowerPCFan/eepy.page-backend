#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

import requests
from pymongo import MongoClient
from simple_python_dotenv import load_dotenv

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
load_dotenv(backend_dir / ".env")


if TYPE_CHECKING:
    from pymongo.collection import Collection
    from src.database.tables.domains import Domains
    from src.dns_.dns import sanitize
    from src.dns_.types import ALLOWED_TYPES
else:
    from database.tables.domains import Domains
    from dns_.dns import sanitize
    from dns_.types import ALLOWED_TYPES


DATABASE_NAME = "database"
USERS_COLLECTION = "eepy.page"
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


def mongo_records(collection: Collection) -> tuple[dict[RecordKey, list[tuple[str, ...]]], dict[RecordKey, set[str]]]:
    records: dict[RecordKey, list[tuple[str, ...]]] = defaultdict(list)
    owners: dict[RecordKey, set[str]] = defaultdict(set)

    for user in collection.find({}, {"domains": 1}):
        user_id = str(user.get("_id", "<unknown>"))
        domains = user.get("domains", [])
        if isinstance(domains, dict):
            domains = [
                {"name": name, **data}
                for name, data in domains.items()
                if isinstance(data, Mapping)
            ]
        if not isinstance(domains, Iterable) or isinstance(domains, (str, bytes)):
            continue

        for domain in domains:
            if not isinstance(domain, Mapping):
                continue
            name = domain.get("name")
            record_type = domain.get("type")
            if not isinstance(name, str) or not isinstance(record_type, str):
                continue
            record_type = record_type.upper()
            if record_type not in ALLOWED_TYPES:
                continue

            key = (Domains.canonical_full_domain_name(name), record_type)
            records[key].append(normalized_values(domain.get("ip", []), record_type))
            owners[key].add(user_id)

    return dict(records), owners


def powerdns_records(session: requests.Session, powerdns_url: str, api_key: str) -> dict[RecordKey, list[tuple[str, ...]]]:
    headers = {"X-API-Key": api_key}
    server_url = f"{powerdns_url}/api/v1/servers/localhost"
    zones_response = session.get(f"{server_url}/zones", headers=headers, timeout=10)
    zones_response.raise_for_status()

    records: dict[RecordKey, list[tuple[str, ...]]] = defaultdict(list)
    for zone in zones_response.json():
        zone_name = zone.get("name")
        if not isinstance(zone_name, str):
            continue

        zone_response = session.get(
            f"{server_url}/zones/{zone_name}",
            headers=headers,
            timeout=10,
        )
        zone_response.raise_for_status()

        for rrset in zone_response.json().get("rrsets", []):
            name = rrset.get("name")
            record_type = rrset.get("type")
            if not isinstance(name, str) or not isinstance(record_type, str):
                continue
            record_type = record_type.upper()
            name = name.rstrip(".").lower()
            if record_type not in ALLOWED_TYPES or not any(name.endswith(tld) for tld in TLDS):
                continue

            values = [
                record.get("content")
                for record in rrset.get("records", [])
                if isinstance(record, Mapping) and isinstance(record.get("content"), str)
            ]
            records[(name, record_type)].append(normalized_values(values, record_type))

    return records


def describe(key: RecordKey) -> str:
    return f"{key[0]} [{key[1]}]"


def print_section(title: str, entries: Iterable[str]) -> int:
    entries = list(entries)
    if not entries:
        return 0
    print(f"\n{title}:")
    for entry in sorted(entries):
        print(f"  {entry}")
    return len(entries)


def main() -> int:
    mongodb_url = os.getenv("MONGODB_URL", "").strip()
    powerdns_url = os.getenv("PDNS_DOMAIN", "").rstrip("/")
    api_key = os.getenv("PDNS_API_KEY", "")
    if not mongodb_url or not powerdns_url or not api_key:
        print("MONGODB_URL, PDNS_DOMAIN, and PDNS_API_KEY must be set", file=sys.stderr)
        return 1

    with MongoClient(mongodb_url) as client, requests.Session() as session:
        collection = client[DATABASE_NAME][USERS_COLLECTION]
        mongo, owners = mongo_records(collection)
        pdns = powerdns_records(session, powerdns_url, api_key)

    mongo_keys = set(mongo)
    pdns_keys = set(pdns)
    issues = 0

    duplicate_mongo = [
        f"{describe(key)} appears {len(values)} times for users {', '.join(sorted(owners[key]))}"
        for key, values in mongo.items()
        if len(values) > 1
    ]
    issues += print_section("Duplicate Mongo records", duplicate_mongo)

    mongo_by_name: dict[str, set[str]] = defaultdict(set)
    pdns_by_name: dict[str, set[str]] = defaultdict(set)
    for name, record_type in mongo_keys:
        mongo_by_name[name].add(record_type)
    for name, record_type in pdns_keys:
        pdns_by_name[name].add(record_type)

    conflicts = []
    for source, records_by_name in (("Mongo", mongo_by_name), ("PowerDNS", pdns_by_name)):
        for name, types in records_by_name.items():
            if "CNAME" in types and len(types) > 1:
                conflicts.append(f"{source}: {name} has incompatible types {', '.join(sorted(types))}")
    issues += print_section("CNAME type conflicts", conflicts)

    missing_from_pdns = [describe(key) for key in sorted(mongo_keys - pdns_keys)]
    issues += print_section("Mongo records missing from PowerDNS", missing_from_pdns)

    missing_from_mongo = [
        describe(key)
        for key in sorted(pdns_keys - mongo_keys)
        if key[0] not in EXCLUDED_NAMES
    ]
    issues += print_section("PowerDNS records missing from Mongo", missing_from_mongo)

    value_mismatches = []
    for key in sorted(mongo_keys & pdns_keys):
        mongo_values = set(mongo[key])
        pdns_values = set(pdns[key])
        if len(mongo_values) != 1 or len(pdns_values) != 1 or next(iter(mongo_values)) != next(iter(pdns_values)):
            value_mismatches.append(
                f"{describe(key)}: Mongo={sorted(mongo_values)} PowerDNS={sorted(pdns_values)}"
            )
    issues += print_section("Value mismatches", value_mismatches)

    duplicate_pdns = [
        f"{describe(key)} has {len(values)} PowerDNS rrsets"
        for key, values in pdns.items()
        if len(values) > 1
    ]
    issues += print_section("Duplicate PowerDNS rrsets", duplicate_pdns)

    print(
        f"Checked {len(mongo_keys)} Mongo keys and {len(pdns_keys)} PowerDNS keys; found {issues} issue(s).",
        file=sys.stderr,
    )
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
