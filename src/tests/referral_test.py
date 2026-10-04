import logging

import pytest

from database.tables.users import Users, UserType

logger = logging.getLogger(__name__)


class TestReferrals:
    def test_creation(self, users: Users, test_user: UserType) -> None:
        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "1")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "ÄÄH")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "1" * 51)

        users.referrals.create(test_user["_id"], "NICE-CODE")
        assert users.referrals.check("nice-code")
        assert users.referrals.check("NICE-code")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "nice-code")

    def test_check(self, users: Users, test_user: UserType) -> None:
        assert users.referrals.check("nice-code")
        assert not users.referrals.check("nice-code2")

    def test_use(self, users: Users, test_user: UserType) -> None:
        current_max_domains = test_user["permissions"]["limits"]["max-domains"] # pyright: ignore[reportTypedDictNotRequiredAccess]

        # 1st referral: referred-count becomes 1, no domain bonus yet
        users.referrals.use(test_user, "nice-code")

        with pytest.raises(ValueError):
            users.referrals.use(test_user, "nice-code2")

        modified_user: UserType = users.find_user({"_id": test_user["_id"]})  # type: ignore
        assert modified_user["permissions"]["limits"]["max-domains"] == current_max_domains # pyright: ignore[reportTypedDictNotRequiredAccess]

        # 2nd referral: referred-count becomes 2, grants +1 domain bonus
        users.referrals.use(test_user, "nice-code")
        modified_user = users.find_user({"_id": test_user["_id"]})  # type: ignore
        assert modified_user["permissions"]["limits"]["max-domains"] == current_max_domains + 1 # pyright: ignore[reportTypedDictNotRequiredAccess]
