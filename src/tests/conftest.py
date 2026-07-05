import os

import pytest

from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from dns_.dns import DNS
from dns_.validation import Validation
from security.encryption import Encryption
from security.session import Session


import secrets
import time

import pymongo
from cryptography.fernet import Fernet

from mail.email import Email


def load_user() -> UserType:
    mock_data: UserType = {
        "_id": "ae5deb822e0d71992900471a7199d0d95b8e7c9d05c40a8245a281fd2c1d6684",
        "email": "gAAAAABmRi2zhJO2MiZ31QY6zpGcrAADAaTgLXZ1AsHeXxCshXwFpelmR0t48PBs0K8EeElL2uZIWPEQd6gkwS81gwJ8o7s-hg49tuB5GctdFmFeEQ2z_H0=",
        "email-hash": "52b13db7b7eec2f5bc592bb11159fbd76d1aa188c1d5bcedc5f993c415fc234e",
        "password": Encryption().create_password("testing"),
        "display-name": "gAAAAABmRi2zSvMOdm3RQWjRidbYB4sQe_qgQNNlnw_zOhttMUHPHowKDHgO3bDbW-5qAbrjWADM5YFimnj2RSb72AmSdhNkaW957Tv_0ZyM0JbO8dqGtj3H5Dt70YXIbalbLLo7AvZqbqvyKD7m4ofJTGkP-JPFKEecucq9eo-nQ_piAuPtieE=",
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
        "last-login": 1743929055,
        "permissions": {"max-domains": 3, "max-subdomains": 2},
        "verified": True,
        "domains": {
            "testing-domains": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "testing-domain2": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "testing-domain3": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "test1[dot]testing-domains": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
            "test2[dot]testing-domains": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140,
            },
        },
        "beta-enroll": False,
        "credits": 400,
        "feature-flags": {"credits": True},
        "api-keys": {
            "00795e160f60a2c94731ceed8fcba87c3949e5d3aa7ccffc55eb7330ab731636": {
                "string": "gAAAAABm4vb60u99B3l6mTZGccDAhfAe3BXqvfRhT5spLhS9LMraIfGVVVfsHZ1kQewtScDeQBuCl7cVgyJFo6Rjondeb_hp-du-UDfskX05gy7wuWGMT3_Qk2OFSBvJdNDLRkitdyBQ",
                "perms": ["delete", "modify"],
                "domains": ["testing-domain"],
                "comment": "Example comment",
            }
        },
        "accessed-from": ["176.93.129.231", "217.152.116.140"],
        "invites": {
            "6MY6Y1YE05Wfkex9": {
                "used": True,
                "used_by": "5350e01c2a017d2e0a3f4664750f4ca22ded5e0ee553a69ebafc246b28d99867",
            },
            "zc8qcUcMLNqE3Dbj": {"used": False},
        },
        "owned-tlds": [],
    }

    return mock_data


# for now i think we're gonna skip this since we dont want to load the actual config for tests and also this wont be in ci/cd
# load_dotenv()

client: pymongo.MongoClient = pymongo.MongoClient(os.getenv("MONGODB_TEST_URL"))

country_data = {
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
    os.environ["ENC_KEY"] = Fernet.generate_key().decode("utf-8")
    os.environ["JWT_KEY"] = secrets.token_urlsafe(64)

    for db in client.list_database_names():
        if db == "admin":
            continue

        dab = client.get_database(db)
        for collection in dab.list_collection_names():
            dab.get_collection(collection).drop()

        client.drop_database(db)
    time.sleep(1)


init_env()

_users = Users(client)
_codes = Codes(client)
_encryption = Encryption(os.environ["ENC_KEY"])
_email = Email(_codes, _users, _encryption)
_domains = Domains(client)
_dns = DNS(_domains)
_validation = Validation(_domains, _dns)
_sessions = Sessions(client)
_rewards = Rewards(client, _users)


def create_first_user() -> None:
    user_id = _users.create_user(
        username="testing",
        password="testing",
        email="testing@email.com",
        language="en-US",
        country=country_data,
        time_signed_up=time.time(),
        email_instance=_email,
        target_url="TESTING_ENV",
        dont_send_email=True,
    )

    _users.modify_document(
        filter={"_id": user_id},
        operation="$set",
        key="verified",
        value=True,
    )

    os.environ["USER_ID"] = user_id


create_first_user()
_test_user = _users.find_user({"_id": _encryption.sha256("testing")})
_test_session = Session.create(
    username=_test_user["_id"],  # pyright: ignore[reportOptionalSubscript]
    real_username="testing",
    mfa_code=None,
    ip="192.168.1.1",
    user_agent="eepy.page-pytest-suite",
    users=_users,
    session_table=_sessions,
)


@pytest.fixture(scope="session")
def mongo_client():
    yield client
    client.close()


@pytest.fixture(scope="session")
def users():
    return _users


@pytest.fixture(scope="session")
def email():
    return _email


@pytest.fixture(scope="session")
def encryption():
    return _encryption


@pytest.fixture(scope="session")
def codes():
    return _codes


@pytest.fixture(scope="session")
def domains():
    return _domains


@pytest.fixture(scope="session")
def validation():
    return _validation


@pytest.fixture(scope="session")
def sessions():
    return _sessions


@pytest.fixture(scope="session")
def rewards():
    return _rewards


@pytest.fixture(scope="session")
def test_session():
    assert _test_session["access_token"]
    return Session(_test_session["access_token"], _users, _sessions)


@pytest.fixture(scope="session")
def test_session_refresh():
    return _test_session["refresh_token"]


@pytest.fixture(scope="session")
def test_user():
    return _test_user
