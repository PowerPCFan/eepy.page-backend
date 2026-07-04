import logging

from security.encryption import Encryption

logger = logging.getLogger(__name__)


class TestEncryption:
    def test_pass_detection(self, encryption: Encryption):
        password = Encryption().create_password("test_password")
        assert Encryption().check_password("test_password", password)
        assert not Encryption().check_password("invalid_password", password)

    def test_verification(self, encryption: Encryption):
        test_encryption = encryption.encrypt("test_string")
        assert encryption.decrypt(test_encryption) == "test_string"

    def test_string_gen(self, encryption: Encryption):
        assert len(Encryption.generate_random_string(16)) == 16

    def test_random_string_randomness(self, encryption: Encryption):
        strings = [encryption.generate_random_string(16) for _ in range(10000)]
        assert len(strings) == len(set(strings))
