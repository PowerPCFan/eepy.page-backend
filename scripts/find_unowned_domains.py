#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
from typing import TYPE_CHECKING

import requests
from sqlmodel import select

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
dotenv = backend_dir / ".env"
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

if TYPE_CHECKING:
    from src.database.session import create_db_engine, session_scope
    from src.models.tables import Domain
else:
    from database.session import create_db_engine, session_scope
    from models.tables import Domain

load_dotenv(dotenv)

TLDS = {"eepy.page", "worksonmymachine.top"}
EXCLUDED_NAMES = {
    itm if any(itm.endswith(tld) for tld in TLDS) else f"{itm}.eepy.page"
    for itm in str(os.getenv("EXCLUDED", "")).split(";")
    if itm
}


def owned_names(postgres_url: str) -> set[str]:
    names: set[str] = set()
    engine = create_db_engine(postgres_url)
    with session_scope(engine) as session:
        for domain_name in session.exec(select(Domain.name)).all():
            if domain_name:
                fqdn = (
                    domain_name
                    if domain_name.endswith(("eepy.page", "worksonmymachine.top"))
                    else f"{domain_name}.eepy.page"
                )
                names.add(fqdn)
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
    postgres_url = os.getenv("POSTGRES_URL", "").strip()
    powerdns_url = os.getenv("PDNS_DOMAIN", "").rstrip("/")
    api_key = os.getenv("PDNS_API_KEY", "")

    if not postgres_url or not powerdns_url or not api_key:
        print("POSTGRES_URL, PDNS_DOMAIN, and PDNS_API_KEY must be set", file=sys.stderr)
        return 1

    with requests.Session() as session:
        owned = owned_names(postgres_url)
        all_powerdns_names = powerdns_names(session, powerdns_url, api_key)

    unowned = sorted(all_powerdns_names - owned - EXCLUDED_NAMES)
    for name in unowned:
        print(name)

    length = len(unowned)
    print(f"Found {length} unowned PowerDNS domain {'names' if length != 1 else 'name'}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
