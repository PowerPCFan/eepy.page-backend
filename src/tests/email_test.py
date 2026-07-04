import logging

from mail.email import Email

logger = logging.getLogger(__name__)


class TestMail:
    def test_use_detection(self, email: Email) -> None:
        assert email.is_taken("testing@email.com")
        assert email.is_taken("testing+alt@email.com")
        assert not email.is_taken("free@email.com")
