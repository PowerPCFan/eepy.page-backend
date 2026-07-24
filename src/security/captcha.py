import logging
from typing import Any

import requests

logger: logging.Logger = logging.getLogger("eepy.page")


class Captcha:
    def __init__(self, turnstile_key: str) -> None:
        self.turnstile_key: str = turnstile_key

    def verify(self, code: str, ip: str) -> bool:
        logger.info("Verifying captcha")
        try:
            response = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                json={"secret": self.turnstile_key, "response": code, "remoteip": ip},
                timeout=5,
            )
        except requests.RequestException:
            logger.exception("Turnstile verification request failed")
            return False

        try:
            data: dict[str, Any] = response.json()
        except requests.JSONDecodeError:
            logger.warning("Turnstile returned invalid JSON")
            return False

        success = data.get("success") is True
        if not success:
            logger.warning("Turnstile verification failed")
            logger.warning(data)
            return False

        logger.info("Captcha passed")
        return True
