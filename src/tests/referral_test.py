import logging
from typing import TYPE_CHECKING

import pytest

from database.models import User
from database.tables.users import Users
from security.encryption import Encryption

if TYPE_CHECKING:
    from tests.conftest import TestUserFactory

logger = logging.getLogger(__name__)


class TestReferrals:
    def test_creation(self, users: Users, test_user: User) -> None:
        with pytest.raises(ValueError):
            users.referrals.create(test_user.id, "1")

        with pytest.raises(ValueError):
            users.referrals.create(test_user.id, "ÄÄH")

        with pytest.raises(ValueError):
            users.referrals.create(test_user.id, "1" * 51)

        users.referrals.create(test_user.id, "NICE-CODE")
        assert users.referrals.check("nice-code")
        assert users.referrals.check("NICE-code")

        with pytest.raises(ValueError):
            users.referrals.create(test_user.id, "nice-code")

    def test_check(self, users: Users, test_user: User) -> None:
        assert users.referrals.check("nice-code")
        assert not users.referrals.check("nice-code2")

    def test_use(
        self,
        users: Users,
        test_user: User,
        insert_test_user: "TestUserFactory",
    ) -> None:
        current_max_domains = test_user.permissions_rel.max_domains if test_user.permissions_rel else 3
        referred_1 = insert_test_user(id=Encryption.sha256("referred_user_1"), verified=True)
        referred_2 = insert_test_user(id=Encryption.sha256("referred_user_2"), verified=True)

        with pytest.raises(ValueError):
            users.referrals.use(test_user, "nice-code")

        users.referrals.use(referred_1, "nice-code")

        with pytest.raises(ValueError):
            users.referrals.use(referred_1, "nice-code")

        with pytest.raises(ValueError):
            users.referrals.use(referred_2, "nice-code2")

        modified_user = users.get_user(test_user.id)
        assert modified_user is not None
        assert modified_user.permissions_rel is not None
        assert modified_user.permissions_rel.max_domains == current_max_domains

        users.referrals.use(referred_2, "nice-code")
        modified_user = users.get_user(test_user.id)
        assert modified_user is not None
        assert modified_user.permissions_rel is not None
        assert modified_user.permissions_rel.max_domains == current_max_domains + 1
