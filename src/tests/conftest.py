from collections.abc import Generator
import secrets
import time
from typing import TYPE_CHECKING, Any, Protocol

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
    UserMFA,
    UserOwnedTLD,
    UserPermissions,
    UserRiskProfile,
)
from database.session import create_db_engine, normalize_postgres_url, set_engine
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import USER_MIGRATION_VERSION, Users
from dns_.dns import DNS
from dns_.validation import Validation
from mail.email import Email
from security.encryption import Encryption
from security.session import Session, SessionCreateStatus

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine


class TestUserFactory(Protocol):
    def __call__(  # noqa: PLR0913
        self,
        *,
        id: str,
        email: str = "",
        email_hash: str | None = None,
        normalized_email_hash: str | None = None,
        password: str | None = None,
        display_name: str = "",
        username: str | None = None,
        lang: str = "en",
        country: dict[str, Any] | None = None,
        created: int = 0,
        last_login: int = 0,
        feature_flags: dict[str, bool] | None = None,
        verified: bool = False,
        migration_version: int = USER_MIGRATION_VERSION,
        permissions: UserPermissions | None = None,
        mfa: UserMFA | None = None,
        owned_tlds: list[str] | None = None,
        domains: list[Domain] | None = None,
        api_keys: list[ApiKey] | None = None,
        risk_profile: UserRiskProfile | None = None,
        devices: list[UserDevice] | None = None,
        alt_links: list[AltLink] | None = None,
    ) -> User: ...


def _resolve_test_db_engine() -> "Engine":
    raw_url = (Environment.postgres_test_url() or "").strip()
    if not raw_url:
        msg = "POSTGRES_TEST_URL must be set to run tests; refusing to fall back to POSTGRES_URL"
        raise RuntimeError(msg)

    prod_url = (Environment.postgres_url() or "").strip()
    if prod_url and normalize_postgres_url(raw_url) == normalize_postgres_url(prod_url):
        msg = "POSTGRES_TEST_URL must not point to the same database as POSTGRES_URL"
        raise RuntimeError(msg)

    candidate = create_db_engine(raw_url, init_tables=False)
    if "localhost" in raw_url:
        try:
            with candidate.connect():
                pass
        except Exception:
            candidate.dispose()
            service_url = raw_url.replace("@localhost:5432/", "@postgres:5432/")
            candidate = create_db_engine(service_url, init_tables=False)
    return candidate


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


@pytest.fixture(scope="session")
def db_engine() -> Generator["Engine"]:
    print("Initializing environment vars")
    Environment.set_value("ENC_KEY", Fernet.generate_key().decode("utf-8"))
    Environment.set_value("JWT_KEY", secrets.token_urlsafe(64))
    Environment.set_value("EMAIL_PEPPER", secrets.token_urlsafe(64))

    engine = _resolve_test_db_engine()
    set_engine(engine)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def users(db_engine: "Engine") -> Users:
    return Users(db_engine)


@pytest.fixture(scope="session")
def codes(db_engine: "Engine") -> Codes:
    return Codes(db_engine)


@pytest.fixture(scope="session")
def encryption(db_engine: "Engine") -> Encryption:
    _ = db_engine
    return Encryption(Environment.enc_key())


@pytest.fixture(scope="session")
def email(codes: Codes, users: Users, encryption: Encryption) -> Email:
    return Email(codes, users, encryption)


@pytest.fixture(scope="session")
def domains(db_engine: "Engine") -> Domains:
    return Domains(db_engine)


@pytest.fixture(scope="session")
def validation(domains: Domains) -> Validation:
    return Validation(domains, DNS(domains))


@pytest.fixture(scope="session")
def sessions(db_engine: "Engine") -> Sessions:
    return Sessions(db_engine)


@pytest.fixture(scope="session")
def rewards(db_engine: "Engine", users: Users) -> Rewards:
    return Rewards(db_engine, users)


@pytest.fixture(scope="session", autouse=True)
def test_user(users: Users, email: Email, encryption: Encryption) -> User:
    user_id = users.create_user(
        username="testing",
        password="testing",
        email="testing@email.com",
        language="en-US",
        country=country_data,
        time_signed_up=round(time.time()),
        email_instance=email,
        target_url="TESTING_ENV",
        dont_send_email=True,
    )
    users.set_verified(user_id, verified=True)
    Environment.set_value("USER_ID", user_id)

    created_user = users.get_user(encryption.sha256("testing"))
    assert created_user is not None
    return created_user


@pytest.fixture(scope="session")
def _test_session_tokens(test_user: User, users: Users, sessions: Sessions) -> SessionCreateStatus:
    return Session.create(
        username=test_user.id,
        real_username="testing",
        mfa_code=None,
        ip="192.168.1.1",
        user_agent="eepy.page-pytest-suite",
        users=users,
        session_table=sessions,
    )


@pytest.fixture(scope="session")
def test_session(
    _test_session_tokens: SessionCreateStatus,
    users: Users,
    sessions: Sessions,
) -> Session:
    assert _test_session_tokens["access_token"]
    return Session(_test_session_tokens["access_token"], users, sessions)


@pytest.fixture(scope="session")
def test_session_refresh(_test_session_tokens: SessionCreateStatus) -> str | None:
    return _test_session_tokens["refresh_token"]


@pytest.fixture
def insert_test_user(
    users: Users,
    sessions: Sessions,
    codes: Codes,
) -> Generator[TestUserFactory]:
    created_ids: list[str] = []
    users.ip_activity.delete_where()
    users.recent_logouts.delete_where()

    def _insert(  # noqa: PLR0913
        *,
        id: str,
        email: str = "",
        email_hash: str | None = None,
        normalized_email_hash: str | None = None,
        password: str | None = None,
        display_name: str = "",
        username: str | None = None,
        lang: str = "en",
        country: dict[str, Any] | None = None,
        created: int = 0,
        last_login: int = 0,
        feature_flags: dict[str, bool] | None = None,
        verified: bool = False,
        migration_version: int = USER_MIGRATION_VERSION,
        permissions: UserPermissions | None = None,
        mfa: UserMFA | None = None,
        owned_tlds: list[str] | None = None,
        domains: list[Domain] | None = None,
        api_keys: list[ApiKey] | None = None,
        risk_profile: UserRiskProfile | None = None,
        devices: list[UserDevice] | None = None,
        alt_links: list[AltLink] | None = None,
    ) -> User:
        users.delete_by_id(id)
        tlds = ["eepy.page"] if owned_tlds is None else owned_tlds
        user_obj = User(
            id=id,
            email=email,
            email_hash=email_hash,
            normalized_email_hash=normalized_email_hash,
            password=password,
            display_name=display_name,
            username=username,
            lang=lang,
            country=dict(country or {}),
            created=created,
            last_login=last_login,
            feature_flags=dict(feature_flags or {}),
            verified=verified,
            migration_version=migration_version,
        )
        user_obj.permissions_rel = permissions or UserPermissions(user_id=id)
        user_obj.mfa = mfa
        user_obj.owned_tlds_rel = [UserOwnedTLD(user_id=id, tld=tld) for tld in tlds]
        user_obj.domains = list(domains or [])
        user_obj.api_keys = list(api_keys or [])
        user_obj.risk_profile = risk_profile or UserRiskProfile(user_id=id)
        user_obj.devices = list(devices or [])

        with users.session() as session:
            user_obj.alt_links = [
                link
                for link in (alt_links or [])
                if link.related_user_id is None or session.get(User, link.related_user_id) is not None
            ]
            session.add(user_obj)
        created_ids.append(id)
        return user_obj

    yield _insert

    for uid in created_ids:
        users.delete_by_id(uid)
        sessions.delete_where(owner=uid)
        codes.delete_where(account=uid)
    users.ip_activity.delete_where()
    users.recent_logouts.delete_where()
