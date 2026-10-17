import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, NotRequired, TypedDict

from pymongo import MongoClient

from database.tables.ip_activity import IPActivity, RecentLogouts

if TYPE_CHECKING:
    from database.tables.users import Users


logger: logging.Logger = logging.getLogger("eepy.page")

AUTO_DISABLE_THRESHOLD = 75
SHARED_IP_EXPIRY_SECONDS = 7 * 86400
IP_ACTIVITY_TTL_SECONDS = 60 * 86400
LOGOUT_VELOCITY_WINDOW_SECONDS = 120


class RiskFlag(TypedDict):
    score: int
    reason: str
    detected_at: int
    permanent: bool
    expires_at: NotRequired[int]


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
    if is_admin:
        return {
            "score": 0,
            "locked": True,
            "disabled": False,
            "disable_reasons": [],
            "flags": {},
            "device_id": device_id,
        }
    return {
        "score": 0,
        "locked": False,
        "disabled": False,
        "disable_reasons": [],
        "flags": {},
        "device_id": device_id,
    }


def calculate_risk_score(risk_data: UserRisk, now: int | None = None) -> int:
    current_time = round(time.time()) if now is None else now
    total = 0
    for flag in risk_data.get("flags", {}).values():
        if not flag.get("permanent", False) and flag.get("expires_at", 0) <= current_time:
            continue
        total += flag.get("score", 0)
    return min(100, max(0, total))


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
        self.recent_logouts.record_logout(user_id, ip, device_id, now)

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
                "reason": f"Shared persistent device token with user {other_device_user['_id'][:10]}...",
                "detected_at": ctx.now,
                "permanent": True,
            }

    def _check_ip_signal(self, ctx: RiskCheckContext) -> None:
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
                "score": 20,
                "reason": f"Shared active IP {ctx.ip} with user {other_user['_id'][:10]}... within 7 days",
                "detected_at": ctx.now,
                "expires_at": ctx.now + SHARED_IP_EXPIRY_SECONDS,
                "permanent": False,
            }

    def _check_rapid_switch_signal(self, ctx: RiskCheckContext) -> None:
        recent_switch = self.recent_logouts.find_recent_switch(ctx.user_id, ctx.ip, ctx.device_id)
        if not recent_switch:
            return
        other_user = ctx.users_table.find_item(
            {
                "_id": recent_switch["user_id"],
                "permissions.admin.enabled": {"$ne": True},
            },
        )
        if other_user:
            ctx.flags["rapid_switch"] = {
                "score": 25,
                "reason": f"Rapid account switch within 120s of logout from user {other_user['_id'][:10]}...",
                "detected_at": ctx.now,
                "permanent": True,
            }

    def evaluate_and_update_risk(
        self,
        user_id: str,
        ip: str,
        device_id: str | None,
        users_table: "Users",
    ) -> UserRisk:
        user = users_table.find_user({"_id": user_id}, find_banned=True)
        if not user:
            return create_default_risk(device_id)

        is_admin = bool(user.get("permissions", {}).get("admin", {}).get("enabled", False))
        risk_data: UserRisk = user.get("risk") or create_default_risk(device_id, is_admin=is_admin)

        if is_admin:
            risk_data["score"] = 0
            risk_data["locked"] = True
            risk_data["disabled"] = False
            users_table.modify_document(filter={"_id": user_id}, operation="$set", key="risk", value=risk_data)
            return risk_data

        now = round(time.time())
        clean_device = device_id.strip() if device_id else None
        if clean_device:
            risk_data["device_id"] = clean_device

        if risk_data.get("locked", False):
            self._update_ip_activity(ip, user_id, now)
            users_table.modify_document(filter={"_id": user_id}, operation="$set", key="risk", value=risk_data)
            return risk_data

        flags = risk_data.setdefault("flags", {})
        ctx = RiskCheckContext(
            user_id=user_id,
            ip=ip,
            device_id=clean_device,
            flags=flags,
            users_table=users_table,
            now=now,
        )
        self._check_device_signal(ctx)
        self._check_ip_signal(ctx)
        self._check_rapid_switch_signal(ctx)

        new_score = calculate_risk_score(risk_data)
        risk_data["score"] = new_score

        if new_score >= AUTO_DISABLE_THRESHOLD and not risk_data.get("disabled", False):
            logger.warning(f"User {user_id} automatically disabled: risk score {new_score} >= {AUTO_DISABLE_THRESHOLD}")
            risk_data["disabled"] = True
            reasons = risk_data.setdefault("disable_reasons", [])
            auto_reason = f"Automated: Risk score {new_score} reached or exceeded threshold ({AUTO_DISABLE_THRESHOLD})"
            if auto_reason not in reasons:
                reasons.append(auto_reason)

        users_table.modify_document(filter={"_id": user_id}, operation="$set", key="risk", value=risk_data)
        self._update_ip_activity(ip, user_id, now)

        return risk_data

    def _update_ip_activity(self, ip: str, user_id: str, timestamp: int) -> None:
        self.ip_activity.record_activity(ip, user_id, timestamp)
