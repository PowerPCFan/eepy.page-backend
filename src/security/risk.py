import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict

from pymongo import MongoClient

from database.tables.ip_activity import (
    IP_ACTIVITY_TTL_SECONDS,
    LOGOUT_VELOCITY_WINDOW_SECONDS,
    IPActivity,
    RecentLogouts,
    normalize_device_id,
)

if TYPE_CHECKING:
    from database.tables.users import Users


logger: logging.Logger = logging.getLogger("eepy.page")

FLAGGED_THRESHOLD = 40
AUTO_DISABLE_THRESHOLD = 80
SHARED_IP_EXPIRY_SECONDS = 7 * 86400

RISK_THRESHOLDS: dict[str, int] = {
    "flagged": FLAGGED_THRESHOLD,
    "auto_disable": AUTO_DISABLE_THRESHOLD,
}

__all__ = [
    "AUTO_DISABLE_THRESHOLD",
    "FLAGGED_THRESHOLD",
    "IP_ACTIVITY_TTL_SECONDS",
    "LOGOUT_VELOCITY_WINDOW_SECONDS",
    "RISK_THRESHOLDS",
    "SHARED_IP_EXPIRY_SECONDS",
    "RiskCheckContext",
    "RiskFlag",
    "RiskManager",
    "UserRisk",
    "calculate_risk_score",
    "create_default_risk",
    "normalize_device_id",
    "prune_expired_flags",
]


class RiskFlag(TypedDict):
    score: int
    reason: str
    detected_at: int
    permanent: bool
    expires_at: NotRequired[int]
    user_id: NotRequired[str]


class UserRisk(TypedDict):
    score: int
    locked: bool
    disabled: bool
    disable_reasons: list[str]
    flags: dict[str, RiskFlag]
    device_id: NotRequired[str | None]


@dataclass(slots=True)
class RiskCheckContext:
    user_id: str
    ip: str
    device_id: str | None
    flags: dict[str, RiskFlag]
    users_table: "Users"
    now: int


def create_default_risk(device_id: str | None = None, is_admin: bool = False) -> UserRisk:
    clean_device = normalize_device_id(device_id)
    if is_admin:
        return {
            "score": 0,
            "locked": True,
            "disabled": False,
            "disable_reasons": [],
            "flags": {},
            "device_id": clean_device,
        }
    return {
        "score": 0,
        "locked": False,
        "disabled": False,
        "disable_reasons": [],
        "flags": {},
        "device_id": clean_device,
    }


def prune_expired_flags(flags: dict[str, RiskFlag], now: int | None = None) -> dict[str, RiskFlag]:
    current_time = round(time.time()) if now is None else now
    return {
        key: flag
        for key, flag in flags.items()
        if flag.get("permanent", False) or flag.get("expires_at", 0) > current_time
    }


def calculate_risk_score(risk_data: UserRisk, now: int | None = None) -> int:
    current_time = round(time.time()) if now is None else now
    total = 0
    for flag in risk_data.get("flags", {}).values():
        if not flag.get("permanent", False) and flag.get("expires_at", 0) <= current_time:
            continue
        total += flag.get("score", 0)
    return min(100, max(0, total))


SHORT_USER_ID_LEN = 10


def _short_user_id(user_id: str) -> str:
    return f"{user_id[:SHORT_USER_ID_LEN]}..." if len(user_id) > SHORT_USER_ID_LEN else user_id


class RiskManager:
    def __init__(
        self,
        mongo_client: MongoClient | None = None,
        ip_activity: "IPActivity | None" = None,
        recent_logouts: "RecentLogouts | None" = None,
    ) -> None:
        if ip_activity is not None and recent_logouts is not None:
            self.ip_activity = ip_activity
            self.recent_logouts = recent_logouts
        elif mongo_client is not None:
            self.ip_activity = IPActivity(mongo_client)
            self.recent_logouts = RecentLogouts(mongo_client)
        else:
            msg = "Either mongo_client or both ip_activity and recent_logouts must be provided"
            raise ValueError(msg)

    def record_logout(self, user_id: str, ip: str, device_id: str | None = None) -> None:
        now = round(time.time())
        self.recent_logouts.record_logout(user_id, ip, normalize_device_id(device_id), now)

    def _check_device_signal(self, ctx: RiskCheckContext) -> None:
        if not ctx.device_id:
            return
        other_device_user = ctx.users_table.find_item(
            {
                "_id": {"$ne": ctx.user_id},
                "risk.device_id": ctx.device_id,
                "permissions.admin.enabled": {"$ne": True},
            },
        )
        if other_device_user:
            ctx.flags["shared_device"] = {
                "score": 50,
                "reason": f"Shared persistent device token with user {_short_user_id(other_device_user['_id'])}",
                "detected_at": ctx.now,
                "permanent": True,
                "user_id": other_device_user["_id"],
            }

    def _check_ip_signal(self, ctx: RiskCheckContext) -> None:
        if not ctx.ip:
            return
        seven_days_ago = ctx.now - SHARED_IP_EXPIRY_SECONDS
        other_ip_activity = self.ip_activity.find_recent_shared_ip(ctx.ip, ctx.user_id, seven_days_ago)
        if not other_ip_activity:
            return
        other_user = ctx.users_table.find_item(
            {
                "_id": other_ip_activity["user_id"],
                "permissions.admin.enabled": {"$ne": True},
            },
        )
        if other_user:
            ctx.flags["shared_recent_ip"] = {
                "score": 25,
                "reason": f"Shared active IP with user {_short_user_id(other_user['_id'])} within 7 days",
                "detected_at": ctx.now,
                "expires_at": ctx.now + SHARED_IP_EXPIRY_SECONDS,
                "permanent": False,
            }

    def _check_rapid_switch_signal(self, ctx: RiskCheckContext) -> None:
        if not ctx.ip and not ctx.device_id:
            return
        since_timestamp = ctx.now - LOGOUT_VELOCITY_WINDOW_SECONDS
        recent_switches = self.recent_logouts.find_recent_switches(
            ctx.user_id,
            ctx.ip,
            ctx.device_id,
            since_timestamp,
        )
        for recent_switch in recent_switches:
            other_user = ctx.users_table.find_item(
                {
                    "_id": recent_switch["user_id"],
                    "permissions.admin.enabled": {"$ne": True},
                },
            )
            if other_user:
                ctx.flags["rapid_switch"] = {
                    "score": 25,
                    "reason": (
                        f"Rapid account switch within {LOGOUT_VELOCITY_WINDOW_SECONDS}s "
                        f"of logout from user {_short_user_id(other_user['_id'])}"
                    ),
                    "detected_at": ctx.now,
                    "permanent": True,
                    "user_id": other_user["_id"],
                }
                break

    @staticmethod
    def _prune_deleted_referenced_users(
        flags: dict[str, RiskFlag],
        users_table: "Users",
    ) -> dict[str, RiskFlag]:
        retained: dict[str, RiskFlag] = {}
        for key, flag in flags.items():
            ref_user_id = flag.get("user_id")
            if (
                ref_user_id
                and key in {"shared_device", "rapid_switch"}
                and users_table.find_item({"_id": ref_user_id}) is None
            ):
                continue
            retained[key] = flag
        return retained

    def evaluate_and_update_risk(
        self,
        user_id: str,
        ip: str,
        device_id: str | None,
        users_table: "Users",
    ) -> UserRisk:
        clean_ip = ip.strip() if ip else ""
        clean_device = normalize_device_id(device_id)

        user = users_table.find_user({"_id": user_id}, find_banned=True)
        if not user:
            return create_default_risk(clean_device)

        is_admin = bool(user.get("permissions", {}).get("admin", {}).get("enabled", False))
        risk_data: UserRisk = user.get("risk") or create_default_risk(clean_device, is_admin=is_admin)

        if is_admin:
            risk_data["score"] = 0
            risk_data["locked"] = True
            risk_data["disabled"] = False
            users_table.table.update_one(
                {"_id": user_id},
                {
                    "$set": {
                        "risk.score": 0,
                        "risk.locked": True,
                        "risk.disabled": False,
                    },
                },
            )
            return risk_data

        now = round(time.time())
        if clean_device:
            risk_data["device_id"] = clean_device

        if risk_data.get("locked", False):
            self._update_ip_activity(clean_ip, user_id, now)
            if clean_device:
                users_table.table.update_one(
                    {"_id": user_id},
                    {"$set": {"risk.device_id": clean_device}},
                )
            return risk_data

        flags = prune_expired_flags(risk_data.get("flags", {}), now=now)
        flags = self._prune_deleted_referenced_users(flags, users_table)
        risk_data["flags"] = flags
        ctx = RiskCheckContext(
            user_id=user_id,
            ip=clean_ip,
            device_id=clean_device,
            flags=flags,
            users_table=users_table,
            now=now,
        )
        self._check_device_signal(ctx)
        self._check_ip_signal(ctx)
        self._check_rapid_switch_signal(ctx)

        new_score = calculate_risk_score(risk_data, now=now)
        risk_data["score"] = new_score

        set_fields: dict[str, Any] = {
            "risk.score": new_score,
            "risk.flags": flags,
        }
        if clean_device:
            set_fields["risk.device_id"] = clean_device

        update_op: dict[str, Any] = {"$set": set_fields}

        if new_score >= AUTO_DISABLE_THRESHOLD and not risk_data.get("disabled", False):
            logger.warning(f"User {user_id} automatically disabled: risk score {new_score} >= {AUTO_DISABLE_THRESHOLD}")
            risk_data["disabled"] = True
            reasons = risk_data.setdefault("disable_reasons", [])
            auto_reason = f"Automated: Risk score {new_score} reached or exceeded threshold ({AUTO_DISABLE_THRESHOLD})"
            if auto_reason not in reasons:
                reasons.append(auto_reason)
            set_fields["risk.disabled"] = True
            update_op["$addToSet"] = {"risk.disable_reasons": auto_reason}

        users_table.table.update_one(
            {"_id": user_id, "risk.locked": {"$ne": True}},
            update_op,
        )
        self._update_ip_activity(clean_ip, user_id, now)

        return risk_data

    def _update_ip_activity(self, ip: str, user_id: str, timestamp: int) -> None:
        if not ip:
            return
        self.ip_activity.record_activity(ip, user_id, timestamp)
