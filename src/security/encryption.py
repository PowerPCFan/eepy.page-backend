import logging
import random
import string
from hashlib import sha256

import argon2
from argon2.exceptions import Argon2Error, InvalidHashError
from cryptography.fernet import Fernet

logger = logging.getLogger("eepy.page")


class Encryption:
    def __init__(self, encryption_key: str | None = None) -> None:
        self.fernet: Fernet | None = Fernet(bytes(encryption_key, "utf-8")) if encryption_key else None
        self.argon = argon2.PasswordHasher()

    @staticmethod
    def sha256(input: str) -> str:
        return sha256(input.encode("utf-8")).hexdigest()

    def create_password(self, plain_password: str) -> str:
        return self.argon.hash(plain_password)

    def check_password(self, password: str, encrypted_password: str) -> bool:
        try:
            return self.argon.verify(encrypted_password, password)
        except (Argon2Error, InvalidHashError):
            return False

    @staticmethod
    def generate_random_string(length: int) -> str:
        return "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(length))

    def encrypt(self, plain_data: str) -> str:
        if not self.fernet:
            msg = "encryption_key not provided to Encryption() instance, so Fernet cannot be used"
            raise ValueError(msg)
        return self.fernet.encrypt(bytes(plain_data, "utf-8")).decode(encoding="utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        if not self.fernet:
            msg = "encryption_key not provided to Encryption() instance, so Fernet cannot be used"
            raise ValueError(msg)
        return self.fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8")
