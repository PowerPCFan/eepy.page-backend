import json
from unittest.mock import MagicMock

import pytest
import requests
from fastapi.exceptions import HTTPException

from security.captcha import Captcha
from server.routes.kofi import Kofi


class TestCaptcha:
    def test_invalid_turnstile_json_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = MagicMock()
        response.json.side_effect = requests.JSONDecodeError("invalid", "", 0)
        monkeypatch.setattr("security.captcha.requests.post", MagicMock(return_value=response))

        assert not Captcha("test-key").verify("captcha-response", "127.0.0.1")

    def test_missing_success_flag_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = MagicMock()
        response.json.return_value = {}
        monkeypatch.setattr("security.captcha.requests.post", MagicMock(return_value=response))

        assert not Captcha("test-key").verify("captcha-response", "127.0.0.1")


class TestKofiWebhook:
    def test_missing_verification_secret_rejects_webhook(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KOFI_VERIFICATION_TOKEN", raising=False)
        kofi = Kofi(MagicMock(), MagicMock())

        with pytest.raises(HTTPException) as exc:
            kofi.webhook(MagicMock(), json.dumps({"verification_token": "submitted"}))

        assert exc.value.status_code == 401

    def test_invalid_webhook_json_returns_422(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KOFI_VERIFICATION_TOKEN", "expected-token")
        kofi = Kofi(MagicMock(), MagicMock())

        with pytest.raises(HTTPException) as exc:
            kofi.webhook(MagicMock(), "{invalid json")

        assert exc.value.status_code == 422

    def test_invalid_webhook_token_rejects_webhook(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KOFI_VERIFICATION_TOKEN", "expected-token")
        kofi = Kofi(MagicMock(), MagicMock())

        with pytest.raises(HTTPException) as exc:
            kofi.webhook(MagicMock(), json.dumps({"verification_token": "wrong-token"}))

        assert exc.value.status_code == 401
