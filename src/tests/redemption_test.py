import logging

from database.tables.reward_codes import Rewards
from database.tables.users import Users, UserType

logger = logging.getLogger(__name__)


class TestRedeeming:
    def test_creation_and_use(
        self,
        rewards: Rewards,
        users: Users,
        test_user: UserType,
    ):
        code = rewards.create("wolf@gang.de", {"$set": {"affected": True}})
        assert not rewards.use(test_user["_id"], code.upper())
        assert rewards.use(test_user["_id"], code)
        assert not rewards.use(test_user["_id"], code), "Code can be used twice!"

        new_user = users.find_user({"_id": test_user["_id"]})
        assert new_user and new_user.get("affected")
