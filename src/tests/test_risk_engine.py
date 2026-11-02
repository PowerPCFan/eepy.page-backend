import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pymongo

from database.table import Table
from database.tables.domains import Domains
from database.tables.ip_activity import (
    EXPIRES_FIELD,
    IP_ACTIVITY_TTL_SECONDS,
    IPActivity,
    RecentLogouts,
    drop_legacy_int_ttl_indexes,
    expiry_from_epoch,
    normalize_device_id,
)
from database.tables.sessions import Sessions
from database.tables.status import Status
from database.tables.users import USER_MIGRATION_VERSION, Users
from dns_.dns import DNS
from mail.email import Email
from security.admin import Admin as AdminTools
from security.encryption import Encryption
from security.risk import (
    AUTO_DISABLE_THRESHOLD,
    FLAGGED_THRESHOLD,
    UserRisk,
    calculate_risk_score,
    create_default_risk,
    prune_expired_flags,
)
from security.session import Session
from server.routes.admin import Admin as AdminRoutes
from server.routes.models.admin import UserDisabledBody


def make_admin_session(
    insert_user: Callable[[dict[str, Any]], dict[str, Any]],
    users: Users,
    sessions: Sessions,
    encryption: Encryption,
    permissions: dict[str, bool],
) -> Session:
    admin_id = Encryption.sha256("pytest_admin_actor")
    insert_user(
        {
            "_id": admin_id,
            "email": encryption.encrypt("admin_actor@example.com"),
            "email-hash": Encryption.sha256("admin_actor@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("admin_actor@example.comsupahcool"),
            "password": encryption.create_password("admin-pass"),
            "display-name": encryption.encrypt("pytest_admin_actor"),
            "username": admin_id,
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "permissions": {
                "admin": {
                    "enabled": True,
                    "permissions": permissions,
                },
            },
            "risk": create_default_risk(is_admin=True),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    access_token, _ = Session.create_session_pair(
        admin_id,
        "pytest-admin-agent",
        "127.0.0.1",
        sessions,
    )
    assert access_token is not None
    return Session(access_token, users, sessions)


def test_create_default_risk_standard_user() -> None:
    risk = create_default_risk(device_id="dev-123", is_admin=False)
    assert risk["score"] == 0
    assert risk["locked"] is False
    assert risk["disabled"] is False
    assert risk["disable_reasons"] == []
    assert risk["flags"] == {}
    assert risk.get("device_id") == "dev-123"


def test_create_default_risk_admin_user() -> None:
    risk = create_default_risk(device_id="dev-admin", is_admin=True)
    assert risk["score"] == 0
    assert risk["locked"] is True
    assert risk["disabled"] is False
    assert risk["disable_reasons"] == []
    assert risk["flags"] == {}
    assert risk.get("device_id") == "dev-admin"


def test_normalize_device_id_validation() -> None:
    assert normalize_device_id("550e8400-e29b-41d4-a716-446655440000") == "550e8400-e29b-41d4-a716-446655440000"
    assert normalize_device_id("  dev_abc123  ") == "dev_abc123"
    assert normalize_device_id("") is None
    assert normalize_device_id("ab") is None  # too short
    assert normalize_device_id("a" * 200) is None  # too long
    assert normalize_device_id("bad$device\n") is None  # invalid chars


def test_calculate_risk_score_sum_and_clamping() -> None:
    now = 1700000000
    risk_data: UserRisk = {
        "score": 0,
        "locked": False,
        "disabled": False,
        "disable_reasons": [],
        "flags": {
            "shared_device": {
                "score": 50,
                "reason": "Shared device",
                "detected_at": now,
                "permanent": True,
            },
            "rapid_switch": {
                "score": 25,
                "reason": "Rapid switch",
                "detected_at": now,
                "permanent": True,
            },
            "shared_recent_ip": {
                "score": 20,
                "reason": "Shared IP",
                "detected_at": now,
                "expires_at": now + 600,
                "permanent": False,
            },
        },
    }

    assert calculate_risk_score(risk_data, now=now) == 95
    assert calculate_risk_score(risk_data, now=now + 700) == 75

    pruned = prune_expired_flags(risk_data["flags"], now=now + 700)
    assert "shared_recent_ip" not in pruned
    assert "shared_device" in pruned

    risk_data["flags"]["another_flag"] = {
        "score": 50,
        "reason": "Extra",
        "detected_at": now,
        "permanent": True,
    }
    assert calculate_risk_score(risk_data, now=now) == 100


def test_ttl_expiry_and_legacy_index_cleanup(mongo_client: pymongo.MongoClient) -> None:
    dt = expiry_from_epoch(1700000000, 60)
    assert isinstance(dt, datetime)
    assert dt.tzinfo == UTC
    assert dt.timestamp() == 1700000060

    temp_coll = mongo_client["database"]["test_ttl_cleanup_temp"]
    temp_coll.drop()
    try:
        temp_coll.create_index([("last_seen", 1)], expireAfterSeconds=5184000)
        temp_coll.create_index([(EXPIRES_FIELD, 1)], expireAfterSeconds=1)
        assert "last_seen_1" in temp_coll.index_information()

        dropped = drop_legacy_int_ttl_indexes(temp_coll, "last_seen")
        assert dropped == ["last_seen_1"]
        assert "last_seen_1" not in temp_coll.index_information()
        assert f"{EXPIRES_FIELD}_1" in temp_coll.index_information()
    finally:
        temp_coll.drop()


def test_evaluate_risk_signals_and_threshold(
    users: Users,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    now = int(time.time())

    user_a = insert_test_user(
        {
            "_id": "aaaa1111222233334444",
            "permissions": {"admin": {"enabled": False}},
            "risk": create_default_risk("device-shared-01"),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    user_b = insert_test_user(
        {
            "_id": "bbbb5555666677778888",
            "permissions": {"admin": {"enabled": False}},
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    users.ip_activity.record_activity("203.0.113.10", user_a["_id"], now - 300)

    risk_b = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="203.0.113.10",
        device_id="device-shared-01",
        users_table=users,
    )
    assert risk_b["score"] == 75
    assert risk_b["score"] >= FLAGGED_THRESHOLD
    assert risk_b["score"] < AUTO_DISABLE_THRESHOLD
    assert risk_b["disabled"] is False
    assert "203.0.113.10" not in risk_b["flags"]["shared_recent_ip"]["reason"]
    assert "aaaa111122..." in risk_b["flags"]["shared_device"]["reason"]
    assert risk_b["flags"]["shared_device"].get("user_id") == user_a["_id"]

    stored_b_doc = users.find_item({"_id": user_b["_id"]})
    assert stored_b_doc is not None
    stored_b = stored_b_doc["risk"]
    assert stored_b["score"] == 75
    assert stored_b["disabled"] is False
    assert stored_b["flags"]["shared_device"]["user_id"] == user_a["_id"]

    users.recent_logouts.record_logout(user_a["_id"], "203.0.113.10", "device-shared-01", now - 30)
    risk_b_after = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="203.0.113.10",
        device_id="device-shared-01",
        users_table=users,
    )
    assert risk_b_after["score"] == 100
    assert risk_b_after["disabled"] is True
    assert "from user aaaa111122..." in risk_b_after["flags"]["rapid_switch"]["reason"]
    assert risk_b_after["flags"]["rapid_switch"].get("user_id") == user_a["_id"]

    stored_b_after_doc = users.find_item({"_id": user_b["_id"]})
    assert stored_b_after_doc is not None
    stored_b_after = stored_b_after_doc["risk"]
    assert stored_b_after["score"] == 100
    assert stored_b_after["disabled"] is True
    assert stored_b_after["flags"]["rapid_switch"]["user_id"] == user_a["_id"]


def test_rapid_switch_outside_window_and_empty_ip(
    users: Users,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    now = int(time.time())

    user_a = insert_test_user(
        {
            "_id": "user_a_id_12345",
            "permissions": {"admin": {"enabled": False}},
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    user_b = insert_test_user(
        {
            "_id": "user_b_id_67890",
            "permissions": {"admin": {"enabled": False}},
            "risk": create_default_risk(),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    users.recent_logouts.record_logout(user_a["_id"], "198.51.100.5", None, now - 121)
    risk_b = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="198.51.100.5",
        device_id=None,
        users_table=users,
    )
    assert "rapid_switch" not in risk_b["flags"]

    users.ip_activity.record_activity("", user_a["_id"], now)
    users.recent_logouts.record_logout(user_a["_id"], "", None, now - 10)
    risk_empty = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="",
        device_id=None,
        users_table=users,
    )
    assert risk_empty["score"] == 0
    assert risk_empty["flags"] == {}


def test_locked_profile_preserves_admin_reenable(
    users: Users,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    now = int(time.time())

    insert_test_user(
        {
            "_id": "user_a_1234567890",
            "permissions": {"admin": {"enabled": False}},
            "risk": create_default_risk("device-shared-99"),
            "migration-version": USER_MIGRATION_VERSION,
        },
    )
    user_b = insert_test_user(
        {
            "_id": "user_b_1234567890",
            "permissions": {"admin": {"enabled": False}},
            "risk": {
                "score": 100,
                "locked": True,
                "disabled": False,
                "disable_reasons": [],
                "flags": {
                    "shared_device": {
                        "score": 50,
                        "reason": "Shared persistent device token with user user_a_123...",
                        "detected_at": now - 100,
                        "permanent": True,
                    },
                },
                "device_id": "device-shared-99",
            },
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    updated = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="203.0.113.50",
        device_id="device-shared-99",
        users_table=users,
    )
    assert updated["disabled"] is False
    assert updated["locked"] is True


def test_ip_activity_and_recent_logouts_subclass_table() -> None:
    assert issubclass(IPActivity, Table)
    assert issubclass(RecentLogouts, Table)


def test_ip_activity_and_recent_logouts_indexes_cleanup_and_datetime_ttl(
    mongo_client: pymongo.MongoClient,
) -> None:
    """Verifies index creation, legacy index drop, legacy document cleanup/backfill,
    and BSON datetime expiresAfter fields against the real test MongoDB."""
    now = int(time.time())
    stale_epoch = now - IP_ACTIVITY_TTL_SECONDS - 100
    fresh_epoch = now - 3600

    db = mongo_client["database"]
    ip_coll = db["ip_activity"]
    logout_coll = db["recent_logouts"]

    ip_coll.drop()
    logout_coll.drop()
    try:
        ip_coll.create_index([("last_seen", 1)], expireAfterSeconds=5184000)
        ip_coll.insert_many(
            [
                {"_id": "1.2.3.4_stale", "ip": "1.2.3.4", "user_id": "stale_u", "last_seen": stale_epoch},
                {"_id": "1.2.3.4_fresh", "ip": "1.2.3.4", "user_id": "fresh_u", "last_seen": fresh_epoch},
            ],
        )

        ip_table = IPActivity(mongo_client)
        ip_indexes = ip_table.table.index_information()
        assert "last_seen_1" not in ip_indexes
        assert f"{EXPIRES_FIELD}_1" in ip_indexes

        assert ip_table.find_item({"_id": "1.2.3.4_stale"}) is None
        fresh_doc = ip_table.find_item({"_id": "1.2.3.4_fresh"})
        assert fresh_doc is not None
        assert isinstance(fresh_doc.get(EXPIRES_FIELD), datetime)

        ip_table.record_activity("203.0.113.5", "user_1", now)
        recorded_ip = ip_table.find_item({"_id": "203.0.113.5_user_1"})
        assert recorded_ip is not None
        assert isinstance(recorded_ip[EXPIRES_FIELD], datetime)

        logout_coll.create_index([("time", 1)], expireAfterSeconds=120)
        logout_coll.insert_one({"user_id": "legacy_u", "ip": "1.2.3.4", "device_id": "dev_1", "time": now - 10})

        logout_table = RecentLogouts(mongo_client)
        logout_indexes = logout_table.table.index_information()
        assert "time_1" not in logout_indexes
        assert f"{EXPIRES_FIELD}_1" in logout_indexes
        assert logout_table.find_item({"user_id": "legacy_u"}) is None

        logout_table.record_logout("user_1", "203.0.113.5", "dev_1234", now)
        recorded_logout = logout_table.find_item({"user_id": "user_1"})
        assert recorded_logout is not None
        assert isinstance(recorded_logout[EXPIRES_FIELD], datetime)
    finally:
        ip_coll.delete_many({})
        logout_coll.delete_many({})


def test_permanent_flags_drop_when_referenced_user_deleted_and_preserve_legacy(
    users: Users,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    now = int(time.time())

    user_b = insert_test_user(
        {
            "_id": "user_b_id",
            "permissions": {"admin": {"enabled": False}},
            "risk": {
                "score": 75,
                "locked": False,
                "disabled": False,
                "disable_reasons": [],
                "flags": {
                    "shared_device": {
                        "score": 50,
                        "reason": "Shared persistent device token with user deleted_us...",
                        "detected_at": now - 500,
                        "permanent": True,
                        "user_id": "deleted_user_id",
                    },
                    "rapid_switch": {
                        "score": 25,
                        "reason": "Rapid account switch within 120s of logout from user legacy_use...",
                        "detected_at": now - 500,
                        "permanent": True,
                        # Legacy flag: no user_id field stored
                    },
                },
                "device_id": "dev-solo-01",
            },
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    updated = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b["_id"],
        ip="198.51.100.25",
        device_id="dev-solo-01",
        users_table=users,
    )
    assert "shared_device" not in updated["flags"]
    assert "rapid_switch" in updated["flags"]
    assert updated["score"] == 25

    stored_b = users.find_item({"_id": user_b["_id"]})
    assert stored_b is not None
    assert stored_b["risk"]["score"] == 25
    assert "shared_device" not in stored_b["risk"]["flags"]


def test_admin_enable_resets_score_and_flags_and_locks_against_stale_overwrite(
    mongo_client: pymongo.MongoClient,
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    now = int(time.time())

    flagged_user = insert_test_user(
        {
            "_id": Encryption.sha256("charlie_flagged"),
            "email": encryption.encrypt("charlie_flagged@example.com"),
            "email-hash": Encryption.sha256("charlie_flagged@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256("charlie_flagged@example.comsupahcool"),
            "password": encryption.create_password("secret"),
            "display-name": encryption.encrypt("charlie_flagged"),
            "username": Encryption.sha256("charlie_flagged"),
            "lang": "en",
            "country": {"country": "US"},
            "created": now - 1000,
            "last-login": now - 100,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "permissions": {"admin": {"enabled": False, "permissions": {}}},
            "risk": {
                "score": 100,
                "locked": False,
                "disabled": True,
                "disable_reasons": ["Automated: Risk score 100 reached or exceeded threshold (80)"],
                "flags": {
                    "shared_device": {
                        "score": 50,
                        "reason": "Shared persistent device token",
                        "detected_at": now - 200,
                        "permanent": True,
                    },
                },
                "device_id": "dev-1234",
            },
            "migration-version": USER_MIGRATION_VERSION,
        },
    )

    dns = DNS(domains)
    status_table = Status(mongo_client)
    admin_tools = AdminTools(users, sessions, domains, dns, email)
    admin_routes = AdminRoutes(users, sessions, status_table, admin_tools)
    admin_session = make_admin_session(
        insert_test_user,
        users,
        sessions,
        encryption,
        {"userdetails": True},
    )

    profile = admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user["_id"], disabled=False),
        session=admin_session,
    )
    assert profile["disabled"] is False
    assert profile["risk"]["score"] == 0
    assert profile["risk"]["flags"] == {}
    assert profile["risk"]["locked"] is True
    assert profile["risk"]["disable_reasons"] == []

    disabled_profile = admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user["_id"], disabled=True, reason=None),
        session=admin_session,
    )
    assert disabled_profile["disabled"] is True

    admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user["_id"], disabled=False),
        session=admin_session,
    )
    users.table.update_one(
        {"_id": flagged_user["_id"], "risk.locked": {"$ne": True}},
        {"$set": {"risk.score": 90, "risk.disabled": True}},
    )
    stored_after = users.find_item({"_id": flagged_user["_id"]})
    assert stored_after is not None
    assert stored_after["risk"]["score"] == 0
    assert stored_after["risk"]["disabled"] is False


def test_get_flagged_users_sorts_by_score_then_username_without_limit(
    mongo_client: pymongo.MongoClient,
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    def make_user(username: str, score: int, disabled: bool = False) -> dict[str, Any]:
        uid = Encryption.sha256(username)
        return {
            "_id": uid,
            "email": encryption.encrypt(f"{username.lower()}@example.com"),
            "email-hash": Encryption.sha256(f"{username.lower()}@example.comsupahcool"),
            "normalized-email-hash": Encryption.sha256(f"{username.lower()}@example.comsupahcool"),
            "password": None,
            "display-name": encryption.encrypt(username),
            "username": Encryption.sha256(username.lower()),
            "lang": "en",
            "country": {"country": "US"},
            "created": 1700000000,
            "last-login": 1700000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
            "permissions": {"admin": {"enabled": False}},
            "risk": {
                "score": score,
                "locked": False,
                "disabled": disabled,
                "disable_reasons": [],
                "flags": {},
            },
            "migration-version": USER_MIGRATION_VERSION,
        }

    for doc in [
        make_user("Zeta", 75),
        make_user("alpha", 75),
        make_user("Bravo", 95, disabled=True),
        make_user("charlie", 75),
        make_user("LowScoreDisabled", 10, disabled=True),
    ]:
        insert_test_user(doc)

    dns = DNS(domains)
    status_table = Status(mongo_client)
    admin_tools = AdminTools(users, sessions, domains, dns, email)
    admin_routes = AdminRoutes(users, sessions, status_table, admin_tools)
    admin_session = make_admin_session(
        insert_test_user,
        users,
        sessions,
        encryption,
        {"userdetails": True},
    )

    flagged = admin_routes.get_flagged_users(session=admin_session)
    assert [u["username"] for u in flagged] == [
        "Bravo",
        "alpha",
        "charlie",
        "Zeta",
        "LowScoreDisabled",
    ]
