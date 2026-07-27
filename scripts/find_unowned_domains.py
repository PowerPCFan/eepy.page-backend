#!/usr/bin/env python3

# overlaps a lot with find_desync so ill probably delete this at some point

from __future__ import annotations

import os
import pathlib
import sys
from collections.abc import Iterable
from typing import TYPE_CHECKING

import requests
from pymongo import MongoClient
from simple_python_dotenv import load_dotenv

if TYPE_CHECKING:
    from pymongo.collection import Collection


scripts_dir = pathlib.Path(__file__).resolve().parent
dotenv = scripts_dir.parent / ".env"
sys.path.insert(0, str(scripts_dir))
load_dotenv(dotenv)

DATABASE_NAME = "database"
USERS_COLLECTION = "eepy.page"
TLDS = {"eepy.page", "worksonmymachine.top"}
EXCLUDED_NAMES = {
    (lambda itm: itm if any(itm.endswith(tld) for tld in TLDS) else f"{itm}.eepy.page")(itm)
    for itm in str(os.getenv("EXCLUDED", "")).split(";")
}


def owned_names(collection: Collection) -> set[str]:
    names: set[str] = set()
    for user in collection.find({}, {"domains": 1}):
        domains = user.get("domains", [])
        if isinstance(domains, dict):
            domains = domains.keys()

        if not isinstance(domains, Iterable) or isinstance(domains, (str, bytes)):
            continue

        for domain in domains:
            if isinstance(domain, str):
                domain_name = domain
            elif isinstance(domain, dict):
                domain_name = domain.get("name")
            else:
                continue

            if isinstance(domain_name, str) and domain_name:
                if not domain_name.endswith(("eepy.page", "worksonmymachine.top")):
                    domain_name += ".eepy.page"
                names.add(domain_name)

    return names


def powerdns_names(session: requests.Session, powerdns_url: str, api_key: str) -> set[str]:
    headers = {"X-API-Key": api_key}
    server_url = f"{powerdns_url}/api/v1/servers/localhost"

    zones_response = session.get(f"{server_url}/zones", headers=headers, timeout=10)
    zones_response.raise_for_status()

    names: set[str] = set()
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
            record_name = rrset.get("name")
            if isinstance(record_name, str) and record_name:
                names.add(record_name.rstrip("."))

    return names


def main() -> int:
    mongodb_url = os.getenv("MONGODB_URL", "").strip()
    powerdns_url = os.getenv("PDNS_DOMAIN", "").rstrip("/")
    api_key = os.getenv("PDNS_API_KEY", "")

    if not mongodb_url or not powerdns_url or not api_key:
        print("MONGODB_URL, PDNS_DOMAIN, and PDNS_API_KEY must be set", file=sys.stderr)
        return 1

    with MongoClient(mongodb_url) as client, requests.Session() as session:
        collection = client[DATABASE_NAME][USERS_COLLECTION]
        owned = owned_names(collection)
        all_powerdns_names = powerdns_names(session, powerdns_url, api_key)

    unowned = sorted(all_powerdns_names - owned - EXCLUDED_NAMES)
    for name in unowned:
        print(name)

    length = len(unowned)
    print(f"Found {length} unowned PowerDNS domain {'names' if length != 1 else 'name'}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
