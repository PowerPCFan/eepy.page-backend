from eepy_page_i18n import normalize_locale, parse_accept_language, resolve_request_locale
from eepy_page_i18n.catalog import SUPPORTED_LOCALES


def is_supported_locale(locale_str: str | None) -> bool:
    if not locale_str:
        return False
    base = locale_str.lower().split("-")[0].split("_")[0].strip()
    return base in SUPPORTED_LOCALES


__all__ = ["is_supported_locale", "normalize_locale", "parse_accept_language", "resolve_request_locale"]
