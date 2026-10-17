import pytest

from database.tables.users import Users, UserType
from security.encryption import Encryption
from server.routes.auth import username_regex


class TestUsernameValidation:
    @pytest.mark.parametrize(
        "valid_username",
        [
            "abc",  # minimum allowed length (3)
            "a_b",
            "a-b",
            "user123",
            "AwesomeUser",
            "test_user",
            "cool-dev-name",
            "user_name-123",
            "12345",
            "a" * 32,  # maximum allowed length (32)
            "user_with_exactly_32_characters",
        ],
    )
    def test_valid_usernames_match_regex(self, valid_username: str) -> None:
        assert username_regex.match(valid_username) is not None

    @pytest.mark.parametrize(
        "invalid_username",
        [
            "",  # empty
            "a",  # too short (<3)
            "ab",  # too short (<3)
            "a" * 33,  # too long (>32)
            "user@email.com",  # contains @ symbol
            "user.name",  # contains dot
            "user name",  # contains space
            " user",  # leading space
            "user ",  # trailing space
            "user!name",  # exclamation mark
            "user#123",  # hash
            "user$money",  # dollar sign
            "user%percent",  # percent
            "user^caret",  # caret
            "user&and",  # ampersand
            "user*star",  # asterisk
            "user(paren)",  # parentheses
            "user+plus",  # plus
            "user=equal",  # equals
            "user[bracket]",  # brackets
            "user/slash",  # slash
            "user\\backslash",  # backslash
            "user:colon",  # colon
            "user;semicolon",  # semicolon
            "user?question",  # question mark
            "käyttäjä",  # non-ASCII unicode
            "user✨",  # emoji
        ],
    )
    def test_invalid_usernames_fail_regex(self, invalid_username: str) -> None:
        assert username_regex.match(invalid_username) is None


class TestCaseInsensitiveUsernameLogin:
    @pytest.mark.parametrize(
        "username_variant",
        [
            "testing",  # exact lowercase
            "Testing",  # capitalized
            "TESTING",  # all uppercase
            "tEsTiNg",  # mixed case 1
            "TeStInG",  # mixed case 2
            " testing ",  # with whitespace
        ],
    )
    def test_case_insensitive_username_finds_user(
        self,
        users: Users,
        test_user: UserType,
        username_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(username_variant)

        assert matched_user is not None
        assert matched_user["_id"] == test_user["_id"]

    @pytest.mark.parametrize(
        "username_variant",
        [
            "testing",
            "Testing",
            "TESTING",
            "tEsTiNg",
        ],
    )
    def test_case_insensitive_username_password_check(
        self,
        users: Users,
        encryption: Encryption,
        username_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(username_variant)
        assert matched_user is not None
        assert matched_user.get("password") is not None
        assert encryption.check_password("testing", matched_user["password"]) is True  # pyright: ignore[reportArgumentType]


class TestCaseInsensitiveEmailLogin:
    @pytest.mark.parametrize(
        "email_variant",
        [
            "testing@email.com",  # exact lowercase
            "Testing@email.com",  # capitalized username
            "TESTING@EMAIL.COM",  # all uppercase
            "Testing@Email.Com",  # title case
            "tEsTiNg@EmAiL.cOm",  # mixed case
            " testing@email.com ",  # with whitespace
        ],
    )
    def test_case_insensitive_email_finds_user(
        self,
        users: Users,
        test_user: UserType,
        email_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(email_variant)

        assert matched_user is not None
        assert matched_user["_id"] == test_user["_id"]

    @pytest.mark.parametrize(
        "email_variant",
        [
            "testing@email.com",
            "Testing@email.com",
            "TESTING@EMAIL.COM",
            "tEsTiNg@EmAiL.cOm",
        ],
    )
    def test_case_insensitive_email_password_check(
        self,
        users: Users,
        encryption: Encryption,
        email_variant: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(email_variant)
        assert matched_user is not None
        assert matched_user.get("password") is not None
        assert encryption.check_password("testing", matched_user["password"]) is True  # pyright: ignore[reportArgumentType]


class TestInvalidLoginIdentifiers:
    @pytest.mark.parametrize(
        "nonexistent_identifier",
        [
            "nonexistent_user",
            "nobody@example.com",
            "testin",
            "testingg",
            "wrong@email.com",
        ],
    )
    def test_nonexistent_identifier_returns_none(
        self,
        users: Users,
        nonexistent_identifier: str,
    ) -> None:
        matched_user: UserType | None = users.find_user_by_identifier(nonexistent_identifier)
        assert matched_user is None

    def test_valid_identifier_with_wrong_password_fails(
        self,
        users: Users,
        encryption: Encryption,
    ) -> None:
        matched_user = users.find_user_by_identifier("testing")
        assert matched_user is not None
        assert encryption.check_password("wrong_password", matched_user["password"]) is False  # pyright: ignore[reportArgumentType]

        matched_email_user = users.find_user_by_identifier("testing@email.com")
        assert matched_email_user is not None
        assert encryption.check_password("wrong_password", matched_email_user["password"]) is False  # pyright: ignore[reportArgumentType]
