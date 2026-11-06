from typing import Any

from pydantic import BaseModel

from .translator import t


class ApiErrorDetail(BaseModel):
    code: str
    message: str


class StandardApiErrorResponse(BaseModel):
    error: ApiErrorDetail


def build_localized_error(
    error_code: str,
    key: str | None = None,
    locale: str | None = None,
    **kwargs: Any,  # noqa: ANN401
) -> dict[str, dict[str, str]]:
    lookup_key = key or f"errors.{error_code}"
    message = t(lookup_key, locale=locale, **kwargs)
    if message.startswith("["):
        alt_key = f"errors.domains.{error_code}"
        alt_msg = t(alt_key, locale=locale, **kwargs)
        if not alt_msg.startswith("["):
            message = alt_msg
        elif error_code.startswith("DOMAIN_"):
            clean_code = error_code[len("DOMAIN_"):]
            domain_alt_key = f"errors.domains.{clean_code}"
            domain_alt_msg = t(domain_alt_key, locale=locale, **kwargs)
            if not domain_alt_msg.startswith("["):
                message = domain_alt_msg
        else:
            auth_key = f"errors.auth.{error_code}"
            auth_msg = t(auth_key, locale=locale, **kwargs)
            if not auth_msg.startswith("["):
                message = auth_msg
            elif error_code.startswith("AUTH_"):
                clean_auth = error_code[len("AUTH_"):]
                auth_alt_key = f"errors.auth.{clean_auth}"
                auth_alt_msg = t(auth_alt_key, locale=locale, **kwargs)
                if not auth_alt_msg.startswith("["):
                    message = auth_alt_msg

    return {
        "error": {
            "code": error_code,
            "message": message,
        },
    }
