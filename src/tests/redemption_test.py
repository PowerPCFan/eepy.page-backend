import logging

from database.models import User
from database.tables.reward_codes import Rewards
from database.tables.users import Users

logger = logging.getLogger(__name__)


class TestRedeeming:
    def test_creation_and_use(
        self,
        rewards: Rewards,
        users: Users,
        test_user: User,
    ) -> None:
        code = rewards.create("wolf@gang.de", {"fields": {"affected": True}})
        assert not rewards.use(test_user.id, code.upper())
        assert rewards.use(test_user.id, code)
        assert not rewards.use(test_user.id, code), "Code can be used twice!"

        new_user = users.get_user(test_user.id)
        assert new_user
        assert new_user.extra_data.get("affected")
