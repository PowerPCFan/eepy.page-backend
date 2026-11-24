import os


class Environment:
    @staticmethod
    def get_arbitrary(key: str, default: str | None = None) -> str | None:
        return os.getenv(key, default)

    @staticmethod
    def set_value(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def delete_value(key: str) -> None:
        os.environ.pop(key, None)

    @staticmethod
    def debug_mode() -> bool:
        return os.getenv("DEBUG_MODE", "False").lower().strip() in {"true", "1", "y", "yes"}

    @staticmethod
    def postgres_url() -> str | None:
        return os.getenv("POSTGRES_URL")

    @staticmethod
    def postgres_test_url() -> str | None:
        return os.getenv("POSTGRES_TEST_URL")

    @staticmethod
    def enc_key() -> str | None:
        return os.getenv("ENC_KEY")

    @staticmethod
    def jwt_key() -> str | None:
        return os.getenv("JWT_KEY")

    @staticmethod
    def email_pepper() -> str:
        return os.getenv("EMAIL_PEPPER", "")

    @staticmethod
    def redis_url() -> str | None:
        return os.getenv("REDIS_URL")

    @staticmethod
    def redis_test_url(default: str = "redis://localhost:6379/15") -> str:
        return os.getenv("REDIS_TEST_URL", default)

    @staticmethod
    def trusted_proxies(default: str = "127.0.0.1/32,::1/128") -> str:
        return os.getenv("TRUSTED_PROXIES", default)

    @staticmethod
    def pdns_api_key() -> str:
        return os.getenv("PDNS_API_KEY") or ""

    @staticmethod
    def pdns_domain() -> str:
        return os.getenv("PDNS_DOMAIN") or ""

    @staticmethod
    def resend_key() -> str | None:
        return os.getenv("RESEND_KEY")

    @staticmethod
    def turnstile_key() -> str:
        return os.getenv("TURNSTILE_KEY") or ""

    @staticmethod
    def ipinfo_key() -> str | None:
        return os.getenv("IPINFO_KEY")

    @staticmethod
    def sentry_dsn() -> str | None:
        return os.getenv("SENTRY_DSN")

    @staticmethod
    def dc_webhook() -> str:
        return os.getenv("DC_WEBHOOK", "")

    @staticmethod
    def kofi_verification_token() -> str | None:
        return os.getenv("KOFI_VERIFICATION_TOKEN")

    @staticmethod
    def started_at() -> float:
        return float(os.getenv("STARTED_AT", "0"))

    @staticmethod
    def start_elapsed() -> str | None:
        return os.getenv("START_ELAPSED")
