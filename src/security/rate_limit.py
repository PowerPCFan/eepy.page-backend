from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

import redis
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from security.convert import parse_headers

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.responses import Response

logger = logging.getLogger("eepy.page")

Scope = Literal["ip", "account", "credential"]


@dataclass(frozen=True)
class Limit:
    max: int
    secs: int
    scope: Scope


@dataclass(frozen=True)
class Policy:
    name: str
    limits: tuple[Limit, ...]


class ScopeEnum(StrEnum):
    IP = "ip"
    ACCOUNT = "account"
    CREDENTIAL = "credential"


class MethodEnum(StrEnum):
    GET = "GET"
    POST = "POST"
    PATCH = "PATCH"
    DELETE = "DELETE"
    PUT = "PUT"

    @staticmethod
    def from_str(value: str) -> MethodEnum:
        try:
            return MethodEnum(value.upper())
        except ValueError:
            msg = f"Invalid HTTP method: {value}"
            raise ValueError(msg)


class PolicyEnum(StrEnum):
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


POLICIES: dict[PolicyEnum, Policy] = {
    PolicyEnum.PUBLIC: Policy(
        name=PolicyEnum.PUBLIC.value,
        limits=(Limit(max=120, secs=60, scope="ip"),),
    ),
    PolicyEnum.STATUS: Policy(
        name=PolicyEnum.STATUS.value,
        limits=(Limit(max=120, secs=60, scope="ip"),),
    ),
    PolicyEnum.AVAILABILITY: Policy(
        name=PolicyEnum.AVAILABILITY.value,
        limits=(Limit(max=60, secs=60, scope="ip"),),
    ),
    PolicyEnum.LOGIN: Policy(
        name=PolicyEnum.LOGIN.value,
        limits=(Limit(max=10, secs=60, scope="ip"),),
    ),
    PolicyEnum.SIGNUP: Policy(
        name=PolicyEnum.SIGNUP.value,
        limits=(Limit(max=3, secs=3600, scope="ip"),),
    ),
    PolicyEnum.RECOVERY: Policy(
        name=PolicyEnum.RECOVERY.value,
        limits=(Limit(max=3, secs=3600, scope="ip"),),
    ),
    PolicyEnum.CODE_CHECK: Policy(
        name=PolicyEnum.CODE_CHECK.value,
        limits=(Limit(max=10, secs=60, scope="ip"),),
    ),
    PolicyEnum.EMAIL: Policy(
        name=PolicyEnum.EMAIL.value,
        limits=(
            Limit(max=3, secs=3600, scope="ip"),
            Limit(max=3, secs=3600, scope="account"),
        ),
    ),
    PolicyEnum.READ: Policy(
        name=PolicyEnum.READ.value,
        limits=(
            Limit(max=240, secs=60, scope="ip"),
            Limit(max=120, secs=60, scope="account"),
        ),
    ),
    PolicyEnum.MUTATION: Policy(
        name=PolicyEnum.MUTATION.value,
        limits=(
            Limit(max=120, secs=60, scope="ip"),
            Limit(max=30, secs=60, scope="account"),
        ),
    ),
    PolicyEnum.DNS_MUTATION: Policy(
        name=PolicyEnum.DNS_MUTATION.value,
        limits=(
            Limit(max=120, secs=60, scope="ip"),
            Limit(max=20, secs=60, scope="credential"),
        ),
    ),
    PolicyEnum.API_READ: Policy(
        name=PolicyEnum.API_READ.value,
        limits=(
            Limit(max=240, secs=60, scope="ip"),
            Limit(max=120, secs=60, scope="credential"),
        ),
    ),
    PolicyEnum.API_MUTATION: Policy(
        name=PolicyEnum.API_MUTATION.value,
        limits=(
            Limit(max=120, secs=60, scope="ip"),
            Limit(max=30, secs=60, scope="credential"),
        ),
    ),
    PolicyEnum.ADMIN_READ: Policy(
        name=PolicyEnum.ADMIN_READ.value,
        limits=(
            Limit(max=240, secs=60, scope="ip"),
            Limit(max=120, secs=60, scope="account"),
        ),
    ),
    PolicyEnum.ADMIN_MUTATION: Policy(
        name=PolicyEnum.ADMIN_MUTATION.value,
        limits=(
            Limit(max=120, secs=60, scope="ip"),
            Limit(max=30, secs=60, scope="account"),
        ),
    ),
    PolicyEnum.WEBHOOK: Policy(
        name=PolicyEnum.WEBHOOK.value,
        limits=(Limit(max=60, secs=60, scope="ip"),),
    ),
}

ROUTE_POLICIES: dict[tuple[MethodEnum, str], PolicyEnum] = {
    (MethodEnum.GET, "/status"): PolicyEnum.STATUS,
    (MethodEnum.POST, "/login"): PolicyEnum.LOGIN,
    (MethodEnum.POST, "/sign-up"): PolicyEnum.SIGNUP,
    (MethodEnum.POST, "/refresh"): PolicyEnum.CODE_CHECK,
    (MethodEnum.PATCH, "/logout"): PolicyEnum.MUTATION,
    (MethodEnum.GET, "/domain/available"): PolicyEnum.AVAILABILITY,
    (MethodEnum.GET, "/api/domain/available"): PolicyEnum.AVAILABILITY,
    (MethodEnum.POST, "/recovery/send"): PolicyEnum.RECOVERY,
    (MethodEnum.POST, "/recovery/verify"): PolicyEnum.CODE_CHECK,
    (MethodEnum.POST, "/email/send"): PolicyEnum.EMAIL,
    (MethodEnum.POST, "/email/verify"): PolicyEnum.CODE_CHECK,
    (MethodEnum.DELETE, "/deletion/send"): PolicyEnum.EMAIL,
    (MethodEnum.DELETE, "/deletion/verify"): PolicyEnum.CODE_CHECK,
    (MethodEnum.POST, "/mfa/verify"): PolicyEnum.CODE_CHECK,
    (MethodEnum.DELETE, "/mfa/recovery"): PolicyEnum.CODE_CHECK,
    (MethodEnum.POST, "/kofi/webhook"): PolicyEnum.WEBHOOK,
}


def get_policy(method: str, path: str) -> Policy:
    method = MethodEnum.from_str(method.upper())
    named_path = "/serveo/tunnels/{tunnel_id}" if path.startswith("/serveo/tunnels/") else path
    policy_name = ROUTE_POLICIES.get((method, named_path))

    if policy_name:
        return POLICIES[policy_name]

    # Set policies based on group and HTTP method
    if path.startswith("/api/"):
        return POLICIES[PolicyEnum.API_READ if method == MethodEnum.GET else PolicyEnum.API_MUTATION]
    if path.startswith("/admin/"):
        return POLICIES[PolicyEnum.ADMIN_READ if method == MethodEnum.GET else PolicyEnum.ADMIN_MUTATION]
    if path.startswith(("/domain/", "/serveo/")):
        return POLICIES[PolicyEnum.READ if method == MethodEnum.GET else PolicyEnum.DNS_MUTATION]
    return POLICIES[PolicyEnum.READ if method == MethodEnum.GET else PolicyEnum.MUTATION]


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


def identity(request: Request, scope: Scope) -> str:
    if scope == "ip":
        return client_ip(request)

    try:
        token = parse_headers(request.headers)
        return f"{scope}:{hashlib.sha256(token.encode()).hexdigest()}"
    except Exception:
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
        for limit in policy.limits:
            subject = identity(request, limit.scope)
            key = f"rate-limit:{policy.name}:{limit.scope}:{subject}:{int(time.time() // limit.secs)}"
            count, retry_after = self.store.consume(key, limit.secs)
            if count > limit.max:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded", "retry_after": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
        return await call_next(request)
