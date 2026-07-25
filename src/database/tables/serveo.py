from collections.abc import Mapping
from typing import Any, TypedDict, cast

from pymongo import MongoClient

from database.tables.users import Users


class ServeoRecord(TypedDict):
    _id: str
    user_id: str
    serveo_auth_record: str
    ssh_fingerprint: str
    subdomain: str
    hostname: str
    service: str
    local_port: int
    command: str
    created_at: int
    updated_at: int


class ServeoTable(Users):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client)

    @staticmethod
    def _tunnel_from_user(user: dict[str, Any]) -> ServeoRecord | None:
        tunnel = user.get("tunnel")
        if not tunnel:
            return None
        return cast("ServeoRecord", {**tunnel, "_id": tunnel["id"], "user_id": user["_id"]})

    def get_tunnel(self, user_id: str, tunnel_id: str) -> ServeoRecord | None:
        if not isinstance(user_id, str) or not isinstance(tunnel_id, str):
            return None
        user = self.table.find_one({"_id": user_id}, {"tunnel": 1})
        if not user or user.get("tunnel", {}).get("id") != tunnel_id:
            return None
        return self._tunnel_from_user(user)

    def save_tunnel(self, document: Mapping[str, Any]) -> None:
        user_id = document["user_id"]
        tunnel = {key: value for key, value in document.items() if key not in {"user_id", "_id"}}
        tunnel["id"] = document["_id"]
        self.table.update_one({"_id": user_id}, {"$set": {"tunnel": tunnel}})

    def replace_tunnel(self, tunnel_id: str, user_id: str, tunnel: Mapping[str, Any]) -> None:
        if tunnel.get("_id") != tunnel_id:
            msg = "Tunnel ID cannot change"
            raise ValueError(msg)
        embedded = {key: value for key, value in tunnel.items() if key not in {"_id", "user_id"}}
        embedded["id"] = tunnel_id
        self.table.update_one({"_id": user_id, "tunnel.id": tunnel_id}, {"$set": {"tunnel": embedded}})

    def remove_tunnel(self, tunnel_id: str, user_id: str) -> None:
        self.table.update_one({"_id": user_id, "tunnel.id": tunnel_id}, {"$unset": {"tunnel": ""}})

    def tunnels(self, user_id: str) -> list[ServeoRecord]:
        user = self.table.find_one({"_id": user_id}, {"tunnel": 1})
        if not user:
            return []
        tunnel = self._tunnel_from_user(user)
        return [] if tunnel is None else [tunnel]
