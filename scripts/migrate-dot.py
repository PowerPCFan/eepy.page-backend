#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import pathlib
from typing import Any

from pymongo import MongoClient

scripts_dir = pathlib.Path(__file__).resolve().parent
dotenv = scripts_dir.parent / ".env"

sys.path.insert(0, str(scripts_dir))
from simple_python_dotenv import load_dotenv
load_dotenv(dotenv)

DATABASE_NAME = "database"
USERS_COLLECTION = "eepy.page"
AVAILABLE_TLDS = ("eepy.page", "worksonmymachine.top")


def canonical_domain_name(domain: str) -> str:
    return domain.replace("[dot]", ".").removesuffix(".").lower()


def canonical_full_domain_name(domain: str) -> str:
    canonical_domain = canonical_domain_name(domain)
    if canonical_domain.endswith(AVAILABLE_TLDS):
        return canonical_domain

    return f"{canonical_domain}.eepy.page"


def normalize_domain_record(domain_name: str, domain_data: dict[str, Any]) -> dict[str, Any]:
    ip = domain_data.get("ip", [])
    return {
        "name": canonical_full_domain_name(domain_name),
        "type": domain_data.get("type", "A"),
        "ip": ip if isinstance(ip, list) else [ip],
        "registered": domain_data.get("registered"),
        "id": domain_data.get("id"),
    }


def normalize_domains(domains: object) -> list[dict[str, Any]]:
    if not domains:
        return []

    if isinstance(domains, list):
        return [
            normalize_domain_record(domain["name"], domain)
            for domain in domains
            if isinstance(domain, dict) and domain.get("name")
        ]

    if isinstance(domains, dict):
        return [
            normalize_domain_record(domain_name, domain_data)
            for domain_name, domain_data in domains.items()
            if isinstance(domain_name, str) and isinstance(domain_data, dict)
        ]

    return []


def normalize_api_keys(api_keys: object) -> dict[str, Any]:
    if not isinstance(api_keys, dict):
        return {}

    normalized_api_keys: dict[str, Any] = {}
    for api_key_hash, api_key in api_keys.items():
        if not isinstance(api_key, dict):
            normalized_api_keys[api_key_hash] = api_key
            continue

        domains = api_key.get("domains", [])
        normalized_domains = [
            domain if domain == "*" else canonical_full_domain_name(domain)
            for domain in domains
            if isinstance(domain, str)
        ]

        normalized_api_keys[api_key_hash] = {
            **api_key,
            "domains": normalized_domains,
        }

    return normalized_api_keys


def main() -> int:
    client = MongoClient(os.getenv("MONGODB_URL", ""))
    apply = bool(sys.argv[1:] and sys.argv[1] == "apply")
    collection = client[DATABASE_NAME][USERS_COLLECTION]

    changed_count = 0
    seen_count = 0

    try:
        for user in collection.find({}):
            seen_count += 1
            normalized_domains = normalize_domains(user.get("domains", []))
            normalized_api_keys = normalize_api_keys(user.get("api-keys", {}))

            updates: dict[str, Any] = {}
            if normalized_domains != user.get("domains", []):
                updates["domains"] = normalized_domains
            if normalized_api_keys != user.get("api-keys", {}):
                updates["api-keys"] = normalized_api_keys

            if not updates:
                print(f"{user.get('_id')}: no changes")
                continue

            changed_count += 1
            print(f"{user.get('_id')}: would update {', '.join(updates)}")
            if apply:
                collection.update_one({"_id": user["_id"]}, {"$set": updates})
    finally:
        client.close()

    action = "Updated" if apply else "Would update"
    print(f"{action} {changed_count} of {seen_count} user document(s).")
    if not apply:
        print("Dry run only. Re-run with apply to write changes.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
