import pytest

from database.table import Table
from database.tables.ip_activity import IPActivity, RecentLogouts
from security.risk import (
    UserRisk,
    calculate_risk_score,
    create_default_risk,
)
from server.routes.models.admin import RiskUpdateBody, UserDisabledBody


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

    risk_data["flags"]["another_flag"] = {
        "score": 50,
        "reason": "Extra",
        "detected_at": now,
        "permanent": True,
    }
    assert calculate_risk_score(risk_data, now=now) == 100


def test_risk_update_body_validation() -> None:
    body = RiskUpdateBody(user_id="user-1", score=80, locked=True, clear_flags=False)
    assert body.user_id == "user-1"
    assert body.score == 80
    assert body.locked is True
    assert body.clear_flags is False

    with pytest.raises(Exception):
        RiskUpdateBody(user_id="user-1", score=150)


def test_user_disabled_body_validation() -> None:
    body = UserDisabledBody(user_id="user-2", disabled=True, reason="Suspected alternate account")
    assert body.user_id == "user-2"
    assert body.disabled is True
    assert body.reason == "Suspected alternate account"


def test_ip_activity_and_recent_logouts_subclass_table() -> None:
    assert issubclass(IPActivity, Table)
    assert issubclass(RecentLogouts, Table)


