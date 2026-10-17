import logging
from typing import TypedDict

from pymongo import MongoClient

from database.table import Table

logger: logging.Logger = logging.getLogger("eepy.page")

IP_ACTIVITY_TTL_SECONDS = 60 * 86400
LOGOUT_VELOCITY_WINDOW_SECONDS = 120


class IPActivityType(TypedDict):
    _id: str
    ip: str
    user_id: str
    last_seen: int


class RecentLogoutType(TypedDict):
    user_id: str
    ip: str
    device_id: str | None
    time: int


class IPActivity(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "ip_activity")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self.table.create_index([("ip", 1), ("last_seen", -1)])
            self.table.create_index([("user_id", 1)])
            self.table.create_index("last_seen", expireAfterSeconds=IP_ACTIVITY_TTL_SECONDS)
        except Exception:
            logger.exception("Failed to create indexes for ip_activity table")

    def record_activity(self, ip: str, user_id: str, timestamp: int) -> None:
        try:
            self.table.update_one(
                {"_id": f"{ip}_{user_id}"},
                {"$set": {"ip": ip, "user_id": user_id, "last_seen": timestamp}},
                upsert=True,
            )
        except Exception:
            logger.exception("Failed to record activity in ip_activity table")

    def find_recent_shared_ip(self, ip: str, user_id: str, since_timestamp: int) -> dict | None:
        return self.table.find_one(
            {
                "ip": ip,
                "user_id": {"$ne": user_id},
                "last_seen": {"$gt": since_timestamp},
            },
        )


class RecentLogouts(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "recent_logouts")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self.table.create_index([("ip", 1)])
            self.table.create_index([("device_id", 1)])
            self.table.create_index([("user_id", 1)])
            self.table.create_index("time", expireAfterSeconds=LOGOUT_VELOCITY_WINDOW_SECONDS)
        except Exception:
            logger.exception("Failed to create indexes for recent_logouts table")

    def record_logout(self, user_id: str, ip: str, device_id: str | None, timestamp: int) -> None:
        try:
            self.insert_document(
                {
                    "user_id": user_id,
                    "ip": ip,
                    "device_id": device_id.strip() if device_id else None,
                    "time": timestamp,
                },
            )
        except Exception:
            logger.exception("Failed to record logout in recent_logouts table")

    def find_recent_switch(self, user_id: str, ip: str, device_id: str | None) -> dict | None:
        query: list[dict] = [{"ip": ip}]
        if device_id:
            query.append({"device_id": device_id.strip()})
        return self.table.find_one(
            {"$or": query, "user_id": {"$ne": user_id}},
        )
