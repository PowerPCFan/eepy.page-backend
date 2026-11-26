from datetime import UTC, datetime
import time
from typing import TYPE_CHECKING

from database.models import AltLink, UserDevice, UserPermissions, UserRiskProfile
from database.table import Table
from database.tables.domains import Domains
from database.tables.ip_activity import (
    EXPIRES_FIELD,
    IPActivity,
    RecentLogouts,
    expiry_from_epoch,
    normalize_device_id,
)
from database.tables.sessions import Sessions
from database.tables.status import Status
from database.tables.users import Users
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
from server.models.admin import UserDisabledBody
from server.routes.admin import Admin as AdminRoutes

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from tests.conftest import TestUserFactory


def make_admin_session(
    insert_user: "TestUserFactory",
    users: Users,
    sessions: Sessions,
    encryption: Encryption,
    permissions: dict[str, bool],
) -> Session:
    admin_id = Encryption.sha256("pytest_admin_actor")
    insert_user(
        id=admin_id,
        email=encryption.encrypt("admin_actor@example.com"),
        email_hash=encryption.hash_email("admin_actor@example.com"),
        normalized_email_hash=encryption.hash_email("admin_actor@example.com"),
        password=encryption.create_password("admin-pass"),
        display_name=encryption.encrypt("pytest_admin_actor"),
        username=admin_id,
        country={"country": "US"},
        created=1700000000,
        last_login=1700000000,
        verified=True,
        permissions=UserPermissions(
            user_id=admin_id,
            admin_enabled=True,
            admin_account=bool(permissions.get("account", False)),
            admin_dns=bool(permissions.get("dns", False)),
            admin_manage_permissions=bool(permissions.get("manage_permissions", False)),
            admin_reports=bool(permissions.get("reports", False)),
            admin_userdetails=bool(permissions.get("userdetails", False)),
            admin_wildcards=bool(permissions.get("wildcards", False)),
        ),
        risk_profile=UserRiskProfile(user_id=admin_id, locked=True),
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


def test_ttl_expiry_helper() -> None:
    dt = expiry_from_epoch(1700000000, 60)
    assert isinstance(dt, datetime)
    assert dt.tzinfo == UTC
    assert dt.timestamp() == 1700000060


def test_evaluate_risk_signals_and_threshold(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())

    user_a = insert_test_user(
        id="aaaa1111222233334444",
        devices=[
            UserDevice(user_id="aaaa1111222233334444", device_id="device-shared-01", first_seen=now, last_seen=now),
        ],
    )
    user_b = insert_test_user(id="bbbb5555666677778888")

    users.ip_activity.record_activity("203.0.113.10", user_a.id, now - 300)

    risk_b = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
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
    assert risk_b["flags"]["shared_device"].get("user_id") == user_a.id

    stored_b_doc = users.get_by_id(user_b.id)
    assert stored_b_doc is not None
    stored_b = stored_b_doc.risk_dict()
    assert stored_b["score"] == 75
    assert stored_b["disabled"] is False
    assert stored_b["flags"]["shared_device"].get("user_id") == user_a.id

    users.recent_logouts.record_logout(user_a.id, "203.0.113.10", "device-shared-01", now - 30)
    risk_b_after = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="203.0.113.10",
        device_id="device-shared-01",
        users_table=users,
    )
    assert risk_b_after["score"] == 100
    assert risk_b_after["disabled"] is True
    assert "from user aaaa111122..." in risk_b_after["flags"]["rapid_switch"]["reason"]
    assert risk_b_after["flags"]["rapid_switch"].get("user_id") == user_a.id

    stored_b_after_doc = users.get_by_id(user_b.id)
    assert stored_b_after_doc is not None
    stored_b_after = stored_b_after_doc.risk_dict()
    assert stored_b_after["score"] == 100
    assert stored_b_after["disabled"] is True
    assert stored_b_after["flags"]["rapid_switch"].get("user_id") == user_a.id


def test_rapid_switch_outside_window_and_empty_ip(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())

    user_a = insert_test_user(id="user_a_id_12345")
    user_b = insert_test_user(id="user_b_id_67890")

    users.recent_logouts.record_logout(user_a.id, "198.51.100.5", None, now - 121)
    risk_b = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="198.51.100.5",
        device_id=None,
        users_table=users,
    )
    assert "rapid_switch" not in risk_b["flags"]

    users.ip_activity.record_activity("", user_a.id, now)
    users.recent_logouts.record_logout(user_a.id, "", None, now - 10)
    risk_empty = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="",
        device_id=None,
        users_table=users,
    )
    assert risk_empty["score"] == 0
    assert risk_empty["flags"] == {}


def test_locked_profile_preserves_admin_reenable(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())

    insert_test_user(
        id="user_a_1234567890",
        devices=[UserDevice(user_id="user_a_1234567890", device_id="device-shared-99", first_seen=now, last_seen=now)],
    )
    user_b = insert_test_user(
        id="user_b_1234567890",
        risk_profile=UserRiskProfile(user_id="user_b_1234567890", score=100, locked=True),
        devices=[UserDevice(user_id="user_b_1234567890", device_id="device-shared-99", first_seen=now, last_seen=now)],
        alt_links=[
            AltLink(
                user_id="user_b_1234567890",
                related_user_id=None,
                signal_type="shared_device",
                score=50,
                reason="Shared persistent device token with user user_a_123...",
                detected_at=now - 100,
                permanent=True,
            ),
        ],
    )

    updated = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="203.0.113.50",
        device_id="device-shared-99",
        users_table=users,
    )
    assert updated["disabled"] is False
    assert updated["locked"] is True


def test_ip_activity_and_recent_logouts_subclass_table() -> None:
    assert issubclass(IPActivity, Table)
    assert issubclass(RecentLogouts, Table)


def test_ip_activity_and_recent_logouts_recording_and_datetime_ttl(
    db_engine: "Engine",
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())
    insert_test_user(id="user_1")
    ip_table = IPActivity(db_engine)
    logout_table = RecentLogouts(db_engine)

    ip_table.delete_where()
    logout_table.delete_where()
    try:
        ip_table.record_activity("203.0.113.5", "user_1", now)
        recorded_ip = ip_table.get_by_id("203.0.113.5_user_1")
        assert recorded_ip is not None
        assert isinstance(getattr(recorded_ip, EXPIRES_FIELD), datetime)

        logout_table.record_logout("user_1", "203.0.113.5", "dev_1234", now)
        recorded_logout = logout_table.find_one(user_id="user_1")
        assert recorded_logout is not None
        assert isinstance(getattr(recorded_logout, EXPIRES_FIELD), datetime)
    finally:
        ip_table.delete_where()
        logout_table.delete_where()


def test_permanent_flags_drop_when_referenced_user_deleted_and_preserve_legacy(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())

    user_b = insert_test_user(
        id="user_b_id",
        risk_profile=UserRiskProfile(user_id="user_b_id", score=75),
        devices=[UserDevice(user_id="user_b_id", device_id="dev-solo-01", first_seen=now, last_seen=now)],
        alt_links=[
            AltLink(
                user_id="user_b_id",
                related_user_id="deleted_user_id",
                signal_type="shared_device",
                score=50,
                reason="Shared persistent device token with user deleted_us...",
                detected_at=now - 500,
                permanent=True,
            ),
            AltLink(
                user_id="user_b_id",
                related_user_id=None,
                signal_type="rapid_switch",
                score=25,
                reason="Rapid account switch within 120s of logout from user legacy_use...",
                detected_at=now - 500,
                permanent=True,
            ),
        ],
    )

    updated = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="198.51.100.25",
        device_id="dev-solo-01",
        users_table=users,
    )
    assert "shared_device" not in updated["flags"]
    assert "rapid_switch" in updated["flags"]
    assert updated["score"] == 25

    stored_b = users.get_by_id(user_b.id)
    assert stored_b is not None
    stored_b_risk = stored_b.risk_dict()
    assert stored_b_risk["score"] == 25
    assert "shared_device" not in stored_b_risk["flags"]


def test_admin_enable_resets_score_and_flags_and_locks_against_stale_overwrite(
    db_engine: "Engine",
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())
    flagged_id = Encryption.sha256("charlie_flagged")

    flagged_user = insert_test_user(
        id=flagged_id,
        email=encryption.encrypt("charlie_flagged@example.com"),
        email_hash=encryption.hash_email("charlie_flagged@example.com"),
        normalized_email_hash=encryption.hash_email("charlie_flagged@example.com"),
        password=encryption.create_password("secret"),
        display_name=encryption.encrypt("charlie_flagged"),
        username=flagged_id,
        country={"country": "US"},
        created=now - 1000,
        last_login=now - 100,
        verified=True,
        risk_profile=UserRiskProfile(
            user_id=flagged_id,
            score=100,
            disabled=True,
            disable_reasons=["Automated: Risk score 100 reached or exceeded threshold (80)"],
        ),
        devices=[UserDevice(user_id=flagged_id, device_id="dev-1234", first_seen=now, last_seen=now)],
        alt_links=[
            AltLink(
                user_id=flagged_id,
                related_user_id=None,
                signal_type="shared_device",
                score=50,
                reason="Shared persistent device token",
                detected_at=now - 200,
                permanent=True,
            ),
        ],
    )

    dns = DNS(domains)
    status_table = Status(db_engine)
    admin_tools = AdminTools(users, sessions, domains, dns, email)
    admin_routes = AdminRoutes(users, sessions, status_table, admin_tools)
    admin_session = make_admin_session(
        insert_test_user,
        users,
        sessions,
        encryption,
        {"account": True},
    )

    profile = admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user.id, disabled=False),
        session=admin_session,
    )
    assert profile.disabled is False
    assert profile.risk["score"] == 0
    assert profile.risk["flags"] == {}
    assert profile.risk["locked"] is True
    assert profile.risk["disable_reasons"] == []

    disabled_profile = admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user.id, disabled=True, reason=None),
        session=admin_session,
    )
    assert disabled_profile.disabled is True

    admin_routes.toggle_user_disabled(
        UserDisabledBody(user_id=flagged_user.id, disabled=False),
        session=admin_session,
    )
    users.save_evaluated_risk(
        flagged_user.id,
        {
            "score": 90,
            "locked": False,
            "disabled": True,
            "disable_reasons": ["Stale"],
            "flags": {},
        },
        only_if_unlocked=True,
    )
    stored_after = users.get_by_id(flagged_user.id)
    assert stored_after is not None
    stored_after_risk = stored_after.risk_dict()
    assert stored_after_risk["score"] == 0
    assert stored_after_risk["disabled"] is False


def test_get_flagged_users_sorts_by_score_then_username_without_limit(
    db_engine: "Engine",
    users: Users,
    sessions: Sessions,
    domains: Domains,
    email: Email,
    encryption: Encryption,
    insert_test_user: "TestUserFactory",
) -> None:
    def add_flagged_user(username: str, score: int, disabled: bool = False) -> None:
        uid = Encryption.sha256(username)
        insert_test_user(
            id=uid,
            email=encryption.encrypt(f"{username.lower()}@example.com"),
            email_hash=encryption.hash_email(f"{username.lower()}@example.com"),
            normalized_email_hash=encryption.hash_email(f"{username.lower()}@example.com"),
            display_name=encryption.encrypt(username),
            username=Encryption.sha256(username.lower()),
            country={"country": "US"},
            created=1700000000,
            last_login=1700000000,
            verified=True,
            risk_profile=UserRiskProfile(user_id=uid, score=score, disabled=disabled),
        )

    add_flagged_user("Zeta", 75)
    add_flagged_user("alpha", 75)
    add_flagged_user("Bravo", 95, disabled=True)
    add_flagged_user("charlie", 75)
    add_flagged_user("LowScoreDisabled", 10, disabled=True)

    dns = DNS(domains)
    status_table = Status(db_engine)
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
    assert [u.username for u in flagged] == [
        "Bravo",
        "alpha",
        "charlie",
        "Zeta",
        "LowScoreDisabled",
    ]


def test_alt_links_relational_graph_and_cascade_delete(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())
    user_a = insert_test_user(
        id="alt_graph_user_a",
        devices=[UserDevice(user_id="alt_graph_user_a", device_id="dev-graph-01", first_seen=now, last_seen=now)],
    )
    user_b = insert_test_user(id="alt_graph_user_b")

    users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="198.51.100.40",
        device_id="dev-graph-01",
        users_table=users,
    )

    links_from_a = users.get_alt_links(user_a.id)
    links_from_b = users.get_alt_links(user_b.id)
    assert len(links_from_a) == 1
    assert len(links_from_b) == 1
    assert links_from_a[0]["signal_type"] == "shared_device"
    assert links_from_a[0]["user_id"] == user_b.id
    assert links_from_a[0]["related_user_id"] == user_a.id

    # Deleting user_a cascades out the alt_links row automatically
    users.delete_by_id(user_a.id)
    assert users.get_alt_links(user_b.id) == []


def test_multiple_devices_tracked_per_user(
    users: Users,
    insert_test_user: "TestUserFactory",
) -> None:
    now = int(time.time())
    user_a = insert_test_user(
        id="multi_dev_user_a",
        devices=[UserDevice(user_id="multi_dev_user_a", device_id="dev-laptop-01", first_seen=now, last_seen=now)],
    )
    user_b = insert_test_user(id="multi_dev_user_b")

    # User A logs in from a second device; the first device must remain tracked
    users.record_device(user_a.id, "dev-phone-02")

    risk_b = users.risk_manager.evaluate_and_update_risk(
        user_id=user_b.id,
        ip="198.51.100.77",
        device_id="dev-laptop-01",
        users_table=users,
    )
    assert "shared_device" in risk_b["flags"]
    assert risk_b["flags"]["shared_device"].get("user_id") == user_a.id
