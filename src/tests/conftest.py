from collections.abc import Callable, Generator, Mapping
import secrets
import time
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet
import pytest

from config.env import Environment
from database.models import (
    AltLink,
    ApiKey,
    Base,
    Domain,
    User,
    UserDevice,
    UserIP,
    UserMFA,
    UserOwnedTLD,
    UserPermissions,
    UserRiskProfile,
)
from database.session import create_db_engine, set_engine
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import USER_MIGRATION_VERSION, Users
from dns_.dns import DNS
from dns_.validation import Validation
from mail.email import Email
from security.encryption import Encryption
from security.session import Session

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine


def _build_user_from_test_doc(doc: Mapping[str, Any]) -> User:
    user_id = str(doc.get("_id") or doc.get("id"))
    user = User(
        id=user_id,
        email=str(doc.get("email", "")),
        email_hash=doc.get("email_hash"),
        normalized_email_hash=doc.get("normalized_email_hash"),
        password=doc.get("password"),
        display_name=str(doc.get("display_name", "")),
        username=doc.get("username"),
        lang=str(doc.get("lang", "en")),
        country=dict(doc.get("country") or {}),
        created=int(doc.get("created", 0)),
        last_login=int(doc.get("last_login", 0)),
        feature_flags=dict(doc.get("feature_flags") or {}),
        verified=bool(doc.get("verified", False)),
        credits=int(doc.get("credits", 200)),
        beta_enroll=bool(doc.get("beta_enroll", False)),
        beta_updated=int(doc.get("beta_updated", 0)),
        invite_code=str(doc.get("invite_code", "")),
        banned=bool(doc.get("banned", False)),
        ban_reasons=list(doc.get("ban_reasons") or []),
        referral_code=str(doc.get("referral_code", "")),
        referred_by=str(doc.get("referred_by", "")),
        referred_count=int(doc.get("referred_count", 0)),
        migration_version=int(doc.get("migration_version", USER_MIGRATION_VERSION)),
    )

    raw_perms = doc.get("permissions")
    perms = UserPermissions(user_id=user_id)
    if isinstance(raw_perms, Mapping):
        limits = raw_perms.get("limits")
        if isinstance(limits, Mapping):
            if limits.get("max_domains") is not None:
                perms.max_domains = int(limits["max_domains"])
            if limits.get("max_subdomains") is not None:
                perms.max_subdomains = int(limits["max_subdomains"])
        features = raw_perms.get("features")
        if isinstance(features, Mapping) and "invite" in features:
            perms.feature_invite = bool(features["invite"])
        admin = raw_perms.get("admin")
        if isinstance(admin, Mapping):
            if "enabled" in admin:
                perms.admin_enabled = bool(admin["enabled"])
            admin_perms = admin.get("permissions")
            if isinstance(admin_perms, Mapping):
                perms.admin_account = bool(admin_perms.get("account", False))
                perms.admin_dns = bool(admin_perms.get("dns", False))
                perms.admin_manage_permissions = bool(admin_perms.get("manage_permissions", False))
                perms.admin_reports = bool(admin_perms.get("reports", False))
                perms.admin_userdetails = bool(admin_perms.get("userdetails", False))
                perms.admin_wildcards = bool(admin_perms.get("wildcards", False))
    user.permissions_rel = perms

    raw_totp = doc.get("totp")
    if isinstance(raw_totp, Mapping) and (raw_totp.get("key") or raw_totp.get("verified")):
        user.mfa = UserMFA(
            user_id=user_id,
            verified=bool(raw_totp.get("verified", False)),
            secret_key=str(raw_totp.get("key") or ""),
            recovery_codes=list(raw_totp.get("recovery") or []),
        )

    raw_tlds = doc.get("owned_tlds")
    tlds = list(raw_tlds) if isinstance(raw_tlds, list) else ["eepy.page"]
    user.owned_tlds_rel = [UserOwnedTLD(user_id=user_id, tld=str(tld)) for tld in tlds]

    raw_ips = doc.get("accessed_from")
    if isinstance(raw_ips, list):
        user.ips = [
            UserIP(user_id=user_id, ip=str(ip), first_seen=idx, last_seen=idx)
            for idx, ip in enumerate(raw_ips)
            if str(ip).strip()
        ]

    raw_domains = doc.get("domains")
    if isinstance(raw_domains, list):
        user.domains = [
            Domain(
                user_id=user_id,
                name=Domains.canonical_full_domain_name(str(d["name"])),
                type=str(d.get("type", "A")).upper(),
                ip=list(d["ip"]) if isinstance(d.get("ip"), list) else [str(d.get("ip", ""))],
                registered=int(d.get("registered", 0)),
            )
            for d in raw_domains
            if isinstance(d, Mapping) and d.get("name")
        ]

    raw_keys = doc.get("api_keys")
    if isinstance(raw_keys, Mapping):
        user.api_keys = [
            ApiKey(
                id=str(key_id),
                user_id=user_id,
                string=str(kd.get("string", "")),
                perms=list(kd.get("perms") or []),
                domains=list(kd.get("domains") or []),
                comment=str(kd.get("comment", "")),
            )
            for key_id, kd in raw_keys.items()
            if isinstance(kd, Mapping)
        ]

    raw_risk = doc.get("risk")
    rp = UserRiskProfile(user_id=user_id)
    if isinstance(raw_risk, Mapping):
        rp.score = int(raw_risk.get("score") or 0)
        rp.locked = bool(raw_risk.get("locked", False))
        rp.disabled = bool(raw_risk.get("disabled", False))
        rp.disable_reasons = list(raw_risk.get("disable_reasons") or [])

        raw_dev = raw_risk.get("device_id")
        if isinstance(raw_dev, str) and raw_dev.strip():
            now_ts = int(time.time())
            user.devices = [UserDevice(user_id=user_id, device_id=raw_dev.strip(), first_seen=now_ts, last_seen=now_ts)]

        raw_flags = raw_risk.get("flags")
        if isinstance(raw_flags, Mapping):
            user.alt_links = [
                AltLink(
                    user_id=user_id,
                    related_user_id=str(fd["user_id"]) if fd.get("user_id") else None,
                    signal_type=str(sig),
                    score=int(fd.get("score") or 0),
                    reason=str(fd.get("reason") or ""),
                    detected_at=int(fd.get("detected_at") or 0),
                    expires_at=int(fd["expires_at"]) if fd.get("expires_at") is not None else None,
                    permanent=bool(fd.get("permanent", False)),
                )
                for sig, fd in raw_flags.items()
                if isinstance(fd, Mapping)
            ]
    user.risk_profile = rp
    return user


def _resolve_test_db_engine() -> "Engine":
    raw_url = Environment.postgres_test_url()
    candidate = create_db_engine(raw_url, init_tables=False)
    if raw_url and "localhost" in raw_url:
        try:
            with candidate.connect():
                pass
        except Exception:
            candidate.dispose()
            service_url = raw_url.replace("@localhost:5432/", "@postgres:5432/")
            candidate = create_db_engine(service_url, init_tables=False)
    return candidate


engine: "Engine" = _resolve_test_db_engine()
set_engine(engine)

country_data: dict[str, Any] = {
    "ip": "176.92.136.59",
    "hostname": "176-92-136-59.example.isp",
    "city": "Helsinki",
    "region": "Uusimaa",
    "country": "FI",
    "loc": "60.1695,24.9354",
    "org": "AS16086 Example ISP",
    "postal": "00100",
    "timezone": "Europe/Helsinki",
    "country_name": "Finland",
    "isEU": True,
    "country_flag_url": "https://cdn.ipinfo.io/static/images/countries-flags/FI.svg",
    "country_flag": {
        "emoji": "🇫🇮",
        "unicode": "U+1F1EB U+1F1EE",
    },
    "country_currency": {"code": "EUR", "symbol": "€"},
    "continent": {"code": "EU", "name": "Europe"},
    "latitude": "60.1695",
    "longitude": "24.9354",
}


def init_env() -> None:
    print("Initializing environment vars")
    Environment.set_value("ENC_KEY", Fernet.generate_key().decode("utf-8"))
    Environment.set_value("JWT_KEY", secrets.token_urlsafe(64))
    Environment.set_value("EMAIL_PEPPER", secrets.token_urlsafe(64))

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


init_env()

_users = Users(engine)
_codes = Codes(engine)
_encryption = Encryption(Environment.enc_key())
_email = Email(_codes, _users, _encryption)
_domains = Domains(engine)
_dns = DNS(_domains)
_validation = Validation(_domains, _dns)
_sessions = Sessions(engine)
_rewards = Rewards(engine, _users)


def create_first_user() -> None:
    user_id = _users.create_user(
        username="testing",
        password="testing",
        email="testing@email.com",
        language="en-US",
        country=country_data,
        time_signed_up=round(time.time()),
        email_instance=_email,
        target_url="TESTING_ENV",
        dont_send_email=True,
    )

    _users.set_verified(user_id, verified=True)
    Environment.set_value("USER_ID", user_id)


create_first_user()
_test_user = _users.get_user(_encryption.sha256("testing"))
assert _test_user is not None
_test_session = Session.create(
    username=_test_user.id,
    real_username="testing",
    mfa_code=None,
    ip="192.168.1.1",
    user_agent="eepy.page-pytest-suite",
    users=_users,
    session_table=_sessions,
)


@pytest.fixture(scope="session")
def db_engine() -> Generator["Engine"]:
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def users() -> Users:
    return _users


@pytest.fixture(scope="session")
def email() -> Email:
    return _email


@pytest.fixture(scope="session")
def encryption() -> Encryption:
    return _encryption


@pytest.fixture(scope="session")
def codes() -> Codes:
    return _codes


@pytest.fixture(scope="session")
def domains() -> Domains:
    return _domains


@pytest.fixture(scope="session")
def validation() -> Validation:
    return _validation


@pytest.fixture(scope="session")
def sessions() -> Sessions:
    return _sessions


@pytest.fixture(scope="session")
def rewards() -> Rewards:
    return _rewards


@pytest.fixture(scope="session")
def test_session() -> Session:
    assert _test_session["access_token"]
    return Session(_test_session["access_token"], _users, _sessions)


@pytest.fixture(scope="session")
def test_session_refresh() -> str | None:
    return _test_session["refresh_token"]


@pytest.fixture(scope="session")
def test_user() -> User | None:
    return _test_user


@pytest.fixture
def insert_test_user(
    users: Users,
    sessions: Sessions,
    codes: Codes,
) -> Generator[Callable[[dict[str, Any]], dict[str, Any]]]:
    created_ids: list[str] = []
    users.ip_activity.delete_where()
    users.recent_logouts.delete_where()

    def _insert(doc: dict[str, Any]) -> dict[str, Any]:
        uid = str(doc["_id"])
        users.delete_by_id(uid)
        user_obj = _build_user_from_test_doc(doc)
        with users.session() as session:
            user_obj.alt_links = [
                link
                for link in user_obj.alt_links
                if link.related_user_id is None or session.get(User, link.related_user_id) is not None
            ]
            session.add(user_obj)
        created_ids.append(uid)
        return doc

    yield _insert

    for uid in created_ids:
        users.delete_by_id(uid)
        sessions.delete_where(owner=uid)
        codes.delete_where(account=uid)
    users.ip_activity.delete_where()
    users.recent_logouts.delete_where()
