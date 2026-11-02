import logging

import email_normalize
import pytest
from pydantic import ValidationError

from database.tables.users import Users, UserType
from mail.email import Email, is_disposable
from security.encryption import Encryption
from server.routes.models.user import SignUp

logger = logging.getLogger(__name__)


class TestMail:
    def test_use_detection(self, email: Email) -> None:
        assert email.is_taken("testing@email.com")
        assert not email.is_taken("free@email.com")

    def test_provider_normalization_detection(self, email: Email, users: Users) -> None:
        users.create_user(
            username="mailtestuser",
            password="testpassword123",
            email="mail.test.user+signup@gmail.com",
            language="en",
            country={"country": "US"},
            time_signed_up=1700000000,
            email_instance=email,
            target_url="test.eepy.page",
            dont_send_email=True,
            skip_verification=True,
        )

        assert email.is_taken("mailtestuser@gmail.com")
        assert email.is_taken("m.a.i.l.t.e.s.t.u.s.e.r@gmail.com")
        assert email.is_taken("mailtestuser+different_tag@gmail.com")
        assert email.is_taken("mailtestuser@googlemail.com")
        assert email.is_taken("MAILTESTUSER+ANOTHER@GMAIL.COM")
        assert not email.is_taken("completelydifferentuser@gmail.com")

    def test_email_storage_and_auth_separation(
        self,
        users: Users,
        email: Email,
        encryption: Encryption,
    ) -> None:
        raw_email = "Test.Norm+MyTag@gmail.com"
        username = "normtestuser"

        user_id = users.create_user(
            username=username,
            password="testpassword123",
            email=raw_email,
            language="en",
            country={"country": "US"},
            time_signed_up=1700000000,
            email_instance=email,
            target_url="test.eepy.page",
            dont_send_email=True,
            skip_verification=True,
        )

        user_data: UserType | None = users.find_user({"_id": user_id})
        assert user_data is not None

        decrypted_email = encryption.decrypt(user_data["email"])
        assert decrypted_email == "Test.Norm+MyTag@gmail.com"

        expected_auth_hash = Encryption.sha256("test.norm+mytag@gmail.comsupahcool")
        assert user_data.get("email-hash") == expected_auth_hash

        expected_norm_hash = Encryption.sha256("testnorm@gmail.comsupahcool")
        assert user_data.get("normalized-email-hash") == expected_norm_hash

        assert users.find_user_by_identifier("Test.Norm+MyTag@gmail.com") is not None
        assert users.find_user_by_identifier("test.norm+mytag@gmail.com") is not None
        assert users.find_user_by_identifier("testnorm@gmail.com") is None

    def test_migration_backfills_normalized_hash(
        self,
        users: Users,
        encryption: Encryption,
    ) -> None:
        mock_id = Encryption.sha256("unmigrated_user")
        raw_email = "Unmigrated.Account+oldtag@gmail.com"

        legacy_doc: UserType = {
            "_id": mock_id,
            "email": encryption.encrypt(raw_email),
            "password": encryption.create_password("testpass"),
            "display-name": encryption.encrypt("unmigrated_user"),
            "username": Encryption.sha256("unmigrated_user"),
            "lang": "en",
            "country": {"country": "US"},
            "email-hash": Encryption.sha256(raw_email + "supahcool"),
            "accessed-from": [],
            "created": 1600000000,
            "last-login": 1600000000,
            "verified": True,
            "domains": [],
            "owned-tlds": ["eepy.page"],
        }
        users.table.insert_one(legacy_doc)

        migrated_user = users.find_user({"_id": mock_id})
        assert migrated_user is not None

        expected_norm_hash = Encryption.sha256("unmigratedaccount@gmail.comsupahcool")
        assert migrated_user.get("normalized-email-hash") == expected_norm_hash

        expected_auth_hash = Encryption.sha256("unmigrated.account+oldtag@gmail.comsupahcool")
        assert migrated_user.get("email-hash") == expected_auth_hash


class TestEmailValidation:
    @pytest.mark.parametrize(
        ("raw_email", "expected_normalized"),
        [
            ("test@example.com", "test@example.com"),
            ("user.name@example.com", "user.name@example.com"),
            ("user+tag@example.com", "user+tag@example.com"),
            ("user_name@example.com", "user_name@example.com"),
            ("user-name@example.com", "user-name@example.com"),
            ("test@sub.example.com", "test@sub.example.com"),
            ("test@example.co.uk", "test@example.co.uk"),
            ("  test@example.com  ", "test@example.com"),
            ("User+Tag@Example.Com", "User+Tag@example.com"),
        ],
    )
    def test_valid_emails_pass_validation(self, raw_email: str, expected_normalized: str) -> None:
        model = SignUp(
            username="validuser",
            password="securepassword123",
            email=raw_email,
            language="en",
        )
        assert model.email == expected_normalized

    @pytest.mark.parametrize(
        "invalid_email",
        [
            "",
            "   ",
            "notanemail",
            "@nodomain.com",
            "nouser@",
            "missingat.com",
            "user@.com",
            "user@domain",
            "user name@example.com",
            "user@example .com",
            "user@@example.com",
        ],
    )
    def test_invalid_emails_fail_validation(self, invalid_email: str) -> None:
        with pytest.raises((ValidationError, ValueError)):
            SignUp(
                username="validuser",
                password="securepassword123",
                email=invalid_email,
                language="en",
            )

    @pytest.mark.parametrize(
        "disposable_email",
        [
            "test@ensproxy.com",  # temp-mail.org
            "test@olipii.com",  # temp-mail.io
            "test@tozya.com",  # tempmail.net
            "test@sharklasers.com",  # guerrillamail.com
            "mailinator.com",
            "user@sub.mailinator.com",
            "user@a.b.mailinator.com",
        ],
    )
    def test_disposable_emails_fail_validation(self, disposable_email: str) -> None:
        assert is_disposable(disposable_email)
        assert Email.is_disposable(disposable_email)

    def test_valid_emails_not_disposable(self) -> None:
        assert not is_disposable("user@gmail.com")
        assert not is_disposable("hello@googlemail.com")
        assert not is_disposable("imagine.still.using@aol.com")
        assert not is_disposable("test.ing@hotmail.com")
        assert not is_disposable("test@proton.me")
        assert not is_disposable("noreply@mail.eepy.page")


class TestEmailNormalization:
    @pytest.mark.parametrize(
        ("input_email", "expected_normalized"),
        [
            ("test.user@gmail.com", "testuser@gmail.com"),
            ("t.e.s.t.u.s.e.r@gmail.com", "testuser@gmail.com"),
            ("testuser+newsletter@gmail.com", "testuser@gmail.com"),
            ("test.user+tag1+tag2@gmail.com", "testuser@gmail.com"),
            ("testuser@googlemail.com", "testuser@gmail.com"),
            ("Test.User+Tag@GoogleMail.COM", "testuser@gmail.com"),
            ("testuser+alias@proton.me", "testuser@proton.me"),
            ("testuser+alias@pm.me", "testuser@pm.me"),
            ("TestUser+Alias@Proton.Me", "testuser@proton.me"),
            ("testuser+alias@outlook.com", "testuser@outlook.com"),
            ("TestUser+Tag@Outlook.COM", "testuser@outlook.com"),
        ],
    )
    def test_provider_normalization(self, input_email: str, expected_normalized: str) -> None:
        result = email_normalize.normalize(input_email.strip(), skip_dns=True)
        assert result.normalized_address.lower() == expected_normalized


