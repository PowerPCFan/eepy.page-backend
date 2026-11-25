from collections.abc import Callable, Generator
import secrets
import time
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet
import pytest

from config.env import Environment
from database.session import create_db_engine, set_engine
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from dns_.dns import DNS
from dns_.validation import Validation
from mail.email import Email
from database.models import Base
from security.encryption import Encryption
from security.session import Session

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine


def load_user() -> UserType:
    mock_data: UserType = {
        "_id": "ae5deb822e0d71992900471a7199d0d95b8e7c9d05c40a8245a281fd2c1d6684",
        "email": "gAAAAABmRi2zhJO2MiZ31QY6zpGcrAADAaTgLXZ1AsHeXxCshXwFpelmR0t48PBs0K8EeElL2uZIWPEQd6gkwS81gwJ8o7s-hg49tuB5GctdFmFeEQ2z_H0=",
        "email_hash": "52b13db7b7eec2f5bc592bb11159fbd76d1aa188c1d5bcedc5f993c415fc234e",
        "password": Encryption().create_password("testing"),
        "display_name": "gAAAAABmRi2zSvMOdm3RQWjRidbYB4sQe_qgQNNlnw_zOhttMUHPHowKDHgO3bDbW-5qAbrjWADM5YFimnj2RSb72AmSdhNkaW957Tv_0ZyM0JbO8dqGtj3H5Dt70YXIbalbLLo7AvZqbqvyKD7m4ofJTGkP-JPFKEecucq9eo-nQ_piAuPtieE=",
        "lang": "fi",
        "country": {
            "ip": "176.93.136.59",
            "hostname": "176-93-136-59.example.isp",
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
            "country_flag": {"emoji": "\ud83c\uddeb\ud83c\uddee", "unicode": "U+1F1EB U+1F1EE"},
            "country_currency": {"code": "EUR", "symbol": "\u20ac"},
            "continent": {"code": "EU", "name": "Europe"},
            "latitude": "60.1695",
            "longitude": "24.9354",
        },
        "created": 1715875251,
        "last_login": 1743929055,
        "permissions": {
            "admin": {"enabled": False, "permissions": {}},
            "limits": {"max_domains": 3, "max_subdomains": 2},
            "features": {"invite": False},
        },
        "verified": True,
        "domains": {
            "testing-domains": {
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "testing-domain2": {
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "testing-domain3": {
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "test1.testing-domains": {
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "test2.testing-domains": {
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
        },
        "beta_enroll": False,
        "credits": 400,
        "feature_flags": {"credits": True},
        "api_keys": {
            "00795e160f60a2c94731ceed8fcba87c3949e5d3aa7ccffc55eb7330ab731636": {
                "string": "gAAAAABm4vb60u99B3l6mTZGccDAhfAe3BXqvfRhT5spLhS9LMraIfGVVVfsHZ1kQewtScDeQBuCl7cVgyJFo6Rjondeb_hp-du-UDfskX05gy7wuWGMT3_Qk2OFSBvJdNDLRkitdyBQ",
                "perms": ["delete", "modify"],
                "domains": ["testing-domain"],
                "comment": "Example comment",
            },
        },
        "accessed_from": ["176.93.129.231", "217.152.116.140"],
        "invites": {
            "6MY6Y1YE05Wfkex9": {
                "used": True,
                "used_by": "5350e01c2a017d2e0a3f4664750f4ca22ded5e0ee553a69ebafc246b28d99867",
            },
            "zc8qcUcMLNqE3Dbj": {"used": False},
        },
        "owned_tlds": [],
    }  # pyright: ignore[reportAssignmentType]

    return mock_data


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

    _users.set_field(
        user_id,
        "verified",
        True,
    )

    Environment.set_value("USER_ID", user_id)


create_first_user()
_test_user = _users.get_user(_encryption.sha256("testing"))
assert _test_user is not None
_test_session = Session.create(
    username=_test_user["_id"],
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
def test_user() -> UserType | None:
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
        users.delete_by_id(doc["_id"])
        users.insert_document(doc)
        created_ids.append(doc["_id"])
        return doc

    yield _insert

    for uid in created_ids:
        users.delete_by_id(uid)
        sessions.delete_where(owner=uid)
        codes.delete_where(account=uid)
    users.ip_activity.delete_where()
    users.recent_logouts.delete_where()
