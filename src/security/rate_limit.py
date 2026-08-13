from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

import redis
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from security.convert import parse_headers
from security.session import Session

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.responses import Response

logger = logging.getLogger("eepy.page")


class Scope(StrEnum):
    IP = "ip"
    ACCOUNT = "account"
    CREDENTIAL = "credential"


@dataclass(frozen=True)
class Limit:
    """
    Represents a rate limit for a specific scope.

    :param max: The maximum number of requests allowed within the specified time window.
    :type max: int

    :param secs: The time window in seconds for which the limit applies.
    :type secs: int

    :param scope: The scope of the limit, which can be one of the following:

        - Scope.IP: The limit applies to the client's IP address.
        - Scope.ACCOUNT: The limit applies to the user's account (if authenticated).
        - Scope.CREDENTIAL: The limit applies to the user's API credentials (if authenticated).

    :type scope: Scope
    """

    max_requests: int
    time_window: int
    scope: Scope


@dataclass(frozen=True)
class Policy:
    name: str
    limits: Limit | tuple[Limit, ...]


class Method(StrEnum):
    GET = "GET"
    POST = "POST"
    PATCH = "PATCH"
    DELETE = "DELETE"
    PUT = "PUT"

    @staticmethod
    def from_str(value: str) -> Method:
        try:
            return Method(value.upper())
        except ValueError:
            msg = f"Invalid HTTP method: {value}"
            raise ValueError(msg)


class PE(StrEnum):
    PUBLIC = "public"
    STATUS = "status"
    AVAILABILITY = "availability"
    LOGIN = "login"
    SIGNUP = "signup"
    RECOVERY = "recovery"
    CODE_CHECK = "code_check"
    EMAIL = "email"
    READ = "read"
    MUTATION = "mutation"
    DNS_MUTATION = "dns_mutation"
    API_READ = "api_read"
    API_MUTATION = "api_mutation"
    ADMIN_READ = "admin_read"
    ADMIN_MUTATION = "admin_mutation"
    WEBHOOK = "webhook"


ONE_DAY = 86400
ONE_MINUTE = 60
ONE_HOUR = 3600


POLICIES: dict[PE, Policy] = {
    PE.PUBLIC: Policy(
        name=PE.PUBLIC.value,
        limits=(
            Limit(
                max_requests=120,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
    PE.STATUS: Policy(
        name=PE.STATUS.value,
        limits=(
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
    PE.AVAILABILITY: Policy(
        name=PE.AVAILABILITY.value,
        limits=(
            Limit(
                max_requests=30,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
    PE.LOGIN: Policy(
        name=PE.LOGIN.value,
        limits=(
            Limit(
                max_requests=5,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
    PE.SIGNUP: Policy(
        name=PE.SIGNUP.value,
        limits=(
            Limit(
                max_requests=3,
                time_window=ONE_HOUR,
                scope=Scope.IP,
            )
        ),
    ),
    PE.RECOVERY: Policy(
        name=PE.RECOVERY.value,
        limits=(
            Limit(
                max_requests=3,
                time_window=ONE_HOUR,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=1,
                time_window=ONE_HOUR,
                scope=Scope.ACCOUNT,
            ),
            Limit(
                max_requests=5,
                time_window=ONE_DAY,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.CODE_CHECK: Policy(
        name=PE.CODE_CHECK.value,
        limits=(
            Limit(
                max_requests=5,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
    PE.EMAIL: Policy(
        name=PE.EMAIL.value,
        limits=(
            Limit(
                max_requests=3,
                time_window=ONE_HOUR,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=3,
                time_window=ONE_HOUR,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.READ: Policy(
        name=PE.READ.value,
        limits=(
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=30,
                time_window=ONE_MINUTE,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.MUTATION: Policy(
        name=PE.MUTATION.value,
        limits=(
            Limit(
                max_requests=45,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=15,
                time_window=ONE_MINUTE,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.DNS_MUTATION: Policy(
        name=PE.DNS_MUTATION.value,
        limits=(
            Limit(
                max_requests=30,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=10,
                time_window=ONE_MINUTE,
                scope=Scope.CREDENTIAL,
            ),
            Limit(
                max_requests=10,
                time_window=ONE_MINUTE,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.API_READ: Policy(
        name=PE.API_READ.value,
        limits=(
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=30,
                time_window=ONE_MINUTE,
                scope=Scope.CREDENTIAL,
            ),
        ),
    ),
    PE.API_MUTATION: Policy(
        name=PE.API_MUTATION.value,
        limits=(
            Limit(
                max_requests=30,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=15,
                time_window=ONE_MINUTE,
                scope=Scope.CREDENTIAL,
            ),
        ),
    ),
    PE.ADMIN_READ: Policy(
        name=PE.ADMIN_READ.value,
        limits=(
            Limit(
                max_requests=120,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.ADMIN_MUTATION: Policy(
        name=PE.ADMIN_MUTATION.value,
        limits=(
            Limit(
                max_requests=120,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            ),
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.ACCOUNT,
            ),
        ),
    ),
    PE.WEBHOOK: Policy(
        name=PE.WEBHOOK.value,
        limits=(
            Limit(
                max_requests=60,
                time_window=ONE_MINUTE,
                scope=Scope.IP,
            )
        ),
    ),
}

ROUTE_POLICIES: dict[tuple[Method, str], PE] = {
    (Method.GET, "/status"): PE.STATUS,
    (Method.POST, "/login"): PE.LOGIN,
    (Method.POST, "/sign-up"): PE.SIGNUP,
    (Method.POST, "/refresh"): PE.CODE_CHECK,
    (Method.PATCH, "/logout"): PE.MUTATION,
    (Method.GET, "/domain/available"): PE.AVAILABILITY,
    (Method.GET, "/api/domain/available"): PE.AVAILABILITY,
    (Method.POST, "/recovery/send"): PE.RECOVERY,
    (Method.POST, "/recovery/verify"): PE.CODE_CHECK,
    (Method.POST, "/email/send"): PE.EMAIL,
    (Method.POST, "/email/verify"): PE.CODE_CHECK,
    (Method.DELETE, "/deletion/send"): PE.EMAIL,
    (Method.DELETE, "/deletion/verify"): PE.CODE_CHECK,
    (Method.POST, "/mfa/verify"): PE.CODE_CHECK,
    (Method.DELETE, "/mfa/recovery"): PE.CODE_CHECK,
    (Method.POST, "/kofi/webhook"): PE.WEBHOOK,
}


def get_policy(method: str, path: str) -> Policy:
    method = Method.from_str(method.upper())
    named_path = "/serveo/tunnels/{tunnel_id}" if path.startswith("/serveo/tunnels/") else path
    policy_name = ROUTE_POLICIES.get((method, named_path))

    if policy_name:
        return POLICIES[policy_name]

    # Set policies based on group and HTTP method
    if path.startswith("/api/"):
        return POLICIES[PE.API_READ if method == Method.GET else PE.API_MUTATION]
    if path.startswith("/admin/"):
        return POLICIES[PE.ADMIN_READ if method == Method.GET else PE.ADMIN_MUTATION]
    if path.startswith(("/domain/", "/serveo/")):
        return POLICIES[PE.READ if method == Method.GET else PE.DNS_MUTATION]
    return POLICIES[PE.READ if method == Method.GET else PE.MUTATION]


class RedisStore:
    _SCRIPT = "local count=redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return {count, redis.call('TTL', KEYS[1])}"  # noqa: E501

    def __init__(self, url: str) -> None:
        self.client = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
        self.client.ping()

    def consume(self, key: str, seconds: int) -> tuple[int, int]:
        count, ttl = self.client.eval(self._SCRIPT, 1, key, seconds)
        return int(count), max(1, int(ttl))


def create_store() -> RedisStore:
    url = os.getenv("REDIS_URL")
    if not url:
        msg = "REDIS_URL must be configured for rate limiting"
        raise RuntimeError(msg)
    try:
        return RedisStore(url)
    except Exception as error:
        msg = "Unable to connect to Redis for rate limiting"
        raise RuntimeError(msg) from error


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def identity(request: Request, scope: Scope) -> str | None:
    if scope == Scope.IP:
        return client_ip(request)

    try:
        token = parse_headers(request.headers)
        if scope == Scope.ACCOUNT:
            account_id = Session.access_token_subject(token)
            if not account_id:
                logger.warning("Unable to determine account for rate limiting; applying IP limit only")
                return None
            return f"account:{hashlib.sha256(account_id.encode()).hexdigest()}"
        return f"{scope}:{hashlib.sha256(token.encode()).hexdigest()}"
    except Exception as error:
        if scope == Scope.ACCOUNT:
            logger.warning("Unable to determine account for rate limiting; applying IP limit only: %s", error)
            return None
        return client_ip(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,  # noqa: ANN001
        store: RedisStore,
    ) -> None:
        super().__init__(app)
        self.store = store

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)
        policy = get_policy(request.method, request.url.path)
        for limit in policy.limits if isinstance(policy.limits, tuple) else (policy.limits,):
            subject = identity(request, limit.scope)
            if subject is None:
                continue
            key = f"rate-limit:{policy.name}:{limit.scope}:{subject}:{int(time.time() // limit.time_window)}"
            count, retry_after = self.store.consume(key, limit.time_window)
            if count > limit.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded", "retry_after": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
        return await call_next(request)
