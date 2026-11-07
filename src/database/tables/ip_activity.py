import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TypedDict

from pymongo import MongoClient, UpdateOne

from database.table import Table

logger: logging.Logger = logging.getLogger("eepy.page")

IP_ACTIVITY_TTL_SECONDS = 60 * 86400
LOGOUT_VELOCITY_WINDOW_SECONDS = 120

EXPIRES_FIELD = "expiresAfter"
BACKFILL_BATCH_SIZE = 1000
DEVICE_ID_REGEX: re.Pattern[str] = re.compile(r"\A[A-Za-z0-9_.:-]{4,128}\Z")


def normalize_device_id(device_id: str | None) -> str | None:
    if not device_id or not isinstance(device_id, str):
        return None
    cleaned = device_id.strip()
    if not DEVICE_ID_REGEX.fullmatch(cleaned):
        return None
    return cleaned


class IPActivityType(TypedDict):
    _id: str
    ip: str
    user_id: str
    last_seen: int
    expiresAfter: datetime


class RecentLogoutType(TypedDict):
    user_id: str
    ip: str | None
    device_id: str | None
    time: int
    expiresAfter: datetime


def expiry_from_epoch(epoch_seconds: float, ttl_seconds: int) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, UTC) + timedelta(seconds=ttl_seconds)


class IPActivity(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "ip_activity")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self.table.create_index([("ip", 1), ("last_seen", -1)])
            self.table.create_index([("user_id", 1)])
            self.delete_in_time(EXPIRES_FIELD)
            self._cleanup_legacy_documents()
        except Exception:
            logger.exception("Failed to initialize TTL and lookup indexes on ip_activity table; continuing startup")

    def _cleanup_legacy_documents(self, now: int | None = None) -> None:
        current_time = round(datetime.now(UTC).timestamp()) if now is None else now
        legacy_filter = {EXPIRES_FIELD: {"$exists": False}}

        deleted = self.table.delete_many(
            {
                **legacy_filter,
                "$or": [
                    {"last_seen": {"$lte": current_time - IP_ACTIVITY_TTL_SECONDS}},
                    {"last_seen": {"$not": {"$type": "number"}}},
                ],
            },
        ).deleted_count

        operations: list[UpdateOne] = []
        backfilled = 0
        for document in self.table.find(legacy_filter, {"last_seen": 1}):
            operations.append(
                UpdateOne(
                    {"_id": document["_id"]},
                    {"$set": {EXPIRES_FIELD: expiry_from_epoch(document["last_seen"], IP_ACTIVITY_TTL_SECONDS)}},
                ),
            )
            if len(operations) >= BACKFILL_BATCH_SIZE:
                backfilled += self.table.bulk_write(operations, ordered=False).modified_count
                operations = []
        if operations:
            backfilled += self.table.bulk_write(operations, ordered=False).modified_count

        if deleted or backfilled:
            logger.info(f"ip_activity legacy cleanup: deleted {deleted}, backfilled {backfilled}")

    def record_activity(self, ip: str, user_id: str, timestamp: int) -> None:
        if not ip:
            return
        try:
            self.table.update_one(
                {"_id": f"{ip}_{user_id}"},
                {
                    "$set": {
                        "ip": ip,
                        "user_id": user_id,
                        "last_seen": timestamp,
                        EXPIRES_FIELD: expiry_from_epoch(timestamp, IP_ACTIVITY_TTL_SECONDS),
                    },
                },
                upsert=True,
            )
        except Exception:
            logger.exception("Failed to record activity in ip_activity table")

    def find_recent_shared_ip(self, ip: str, user_id: str, since_timestamp: int) -> dict | None:
        if not ip:
            return None
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
            self.delete_in_time(EXPIRES_FIELD)
            removed = self.table.delete_many({EXPIRES_FIELD: {"$exists": False}}).deleted_count
            if removed:
                logger.info(f"recent_logouts legacy cleanup: deleted {removed}")
        except Exception:
            logger.exception("Failed to initialize TTL and lookup indexes on recent_logouts table; continuing startup")

    def record_logout(self, user_id: str, ip: str | None, device_id: str | None, timestamp: int) -> None:
        clean_ip = ip.strip() if ip else None
        clean_device = normalize_device_id(device_id)
        if not clean_ip and not clean_device:
            return
        try:
            self.insert_document(
                {
                    "user_id": user_id,
                    "ip": clean_ip or None,
                    "device_id": clean_device,
                    "time": timestamp,
                    EXPIRES_FIELD: expiry_from_epoch(timestamp, LOGOUT_VELOCITY_WINDOW_SECONDS),
                },
            )
        except Exception:
            logger.exception("Failed to record logout in recent_logouts table")

    def find_recent_switches(
        self,
        user_id: str,
        ip: str | None,
        device_id: str | None,
        since_timestamp: int,
        limit: int = 5,
    ) -> list[dict]:
        query: list[dict] = []
        clean_ip = ip.strip() if ip else ""
        clean_device = normalize_device_id(device_id)
        if clean_ip:
            query.append({"ip": clean_ip})
        if clean_device:
            query.append({"device_id": clean_device})
        if not query:
            return []

        cursor = (
            self.table.find(
                {
                    "$or": query,
                    "user_id": {"$ne": user_id},
                    "time": {"$gte": since_timestamp},
                },
            )
            .sort("time", -1)
            .limit(limit)
        )
        return list(cursor)
