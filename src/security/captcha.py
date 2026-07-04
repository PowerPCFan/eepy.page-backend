import json
import logging
from typing import Any

import requests

logger: logging.Logger = logging.getLogger("eepy.page")


class Captcha:
    def __init__(self, turnstile_key: str) -> None:
        self.turnstile_key: str = turnstile_key

    def verify(self, code: str, ip: str) -> bool:
        logger.info("Verifying captcha")
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=json.dumps(
                {"secret": self.turnstile_key, "response": code, "remoteip": ip},
            ),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )

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
