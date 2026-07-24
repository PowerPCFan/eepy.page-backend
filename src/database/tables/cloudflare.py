import time
from typing import Any, TypedDict

from pymongo import MongoClient

from database.table import Table


class CloudflareConnection(TypedDict, total=False):
    _id: str
    user_id: str
    cloudflare_account_id: str
    access_token: str
    refresh_token: str | None
    expires_at: int | None
    oauth_state_hash: str | None
    created_at: int
    updated_at: int


class CloudflareTunnel(TypedDict, total=False):
    _id: str
    user_id: str
    cloudflare_tunnel_id: str
    cloudflare_account_id: str
    subdomain: str
    hostname: str
    service: str
    created_at: int
    updated_at: int


class Cloudflare(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "cloudflare")
        self.table.create_index("user_id")
        self.table.create_index([("user_id", 1), ("hostname", 1)], unique=True)

    def connection(self, user_id: str) -> CloudflareConnection | None:
        return self.find_item({"_id": f"connection:{user_id}"})  # pyright: ignore[reportReturnType]

    def save_connection(self, user_id: str, values: dict[str, Any]) -> None:
        now = int(time.time())
        self.table.update_one(
            {"_id": f"connection:{user_id}"},
            {"$set": {**values, "user_id": user_id, "updated_at": now}, "$setOnInsert": {"created_at": now}},
            upsert=True,
        )

    def delete_connection(self, user_id: str) -> None:
        self.delete_document({"_id": f"connection:{user_id}"})

    def tunnels(self, user_id: str) -> list[CloudflareTunnel]:
        return self.find_items({"user_id": user_id, "_id": {"$not": {"$regex": "^connection:"}}})  # pyright: ignore[reportReturnType]
