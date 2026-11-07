from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

import redis
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from mail.email import normalize_email_address
from security.convert import parse_headers
from security.session import Session

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.responses import Response

logger = logging.getLogger("eepy.page")

DEFAULT_TRUSTED_PROXIES = "127.0.0.1,::1,testclient"
MAX_RATE_LIMIT_BODY_BYTES = 16384


class Scope(StrEnum):
    IP = "ip"
    ACCOUNT = "account"
    CREDENTIAL = "credential"
    TARGET = "target"


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
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"

    @staticmethod
    def from_str(value: str) -> Method:
        try:
            return Method(value.upper())
        except ValueError:
            msg = f"Invalid HTTP method: {value}"
            raise ValueError(msg)

    @staticmethod
    def get_equivalents(method: Method) -> Method:
        if method == Method.HEAD:
            return Method.GET
        return method


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
            ),
            Limit(
                max_requests=5,
                time_window=ONE_MINUTE,
                scope=Scope.TARGET,
            ),
            Limit(
                max_requests=20,
                time_window=ONE_HOUR,
                scope=Scope.TARGET,
            ),
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
                scope=Scope.TARGET,
            ),
            Limit(
                max_requests=5,
                time_window=ONE_DAY,
                scope=Scope.TARGET,
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
            ),
            Limit(
                max_requests=5,
                time_window=ONE_MINUTE,
                scope=Scope.TARGET,
            ),
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
    (Method.DELETE, "/mfa/delete"): PE.CODE_CHECK,
    (Method.DELETE, "/mfa/recovery"): PE.CODE_CHECK,
    (Method.POST, "/redeem"): PE.CODE_CHECK,
    (Method.POST, "/kofi/webhook"): PE.WEBHOOK,
}


def get_policy(method: str, path: str) -> Policy:
    method = Method.get_equivalents(Method.from_str(method.upper()))
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


def _is_trusted_proxy(host: str) -> bool:
    if not host:
        return False
    raw_proxies = os.getenv("TRUSTED_PROXIES", DEFAULT_TRUSTED_PROXIES)
    entries = [item.strip() for item in raw_proxies.split(",") if item.strip()]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host in entries

    for entry in entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if host == entry:
                return True
    return False


def client_ip(request: Request, default: str = "unknown") -> str:
    direct_host = request.client.host.strip() if request.client and request.client.host else ""
    if not direct_host:
        return default

    if not _is_trusted_proxy(direct_host):
        return direct_host

    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        hops: list[str] = []
        for raw_hop in forwarded.split(","):
            hop = raw_hop.strip()
            if not hop:
                continue
            try:
                ipaddress.ip_address(hop)
                hops.append(hop)
            except ValueError:
                continue
        if hops:
            for hop in reversed(hops):
                if not _is_trusted_proxy(hop):
                    return hop
            return hops[0]

    return direct_host


def normalize_target_identifier(identifier: str) -> str:
    cleaned = identifier.strip()
    if not cleaned:
        return ""
    if "@" in cleaned:
        return normalize_email_address(cleaned)
    return cleaned.lower()


def hash_target_identifier(identifier: str) -> str | None:
    normalized = normalize_target_identifier(identifier)
    if not normalized:
        return None
    return f"target:{hashlib.sha256(normalized.encode()).hexdigest()}"


async def extract_target_identifier(request: Request) -> str | None:
    for param in ("username", "email", "user_id"):
        val = request.query_params.get(param)
        if isinstance(val, str) and val.strip():
            return hash_target_identifier(val)

    if request.method in {"POST", "DELETE", "PATCH", "PUT"}:
        try:
            body_bytes = await request.body()
            if body_bytes and len(body_bytes) <= MAX_RATE_LIMIT_BODY_BYTES:
                payload = json.loads(body_bytes)
                if isinstance(payload, dict):
                    for key in ("username", "email", "user_id"):
                        raw_val = payload.get(key)
                        if isinstance(raw_val, str) and raw_val.strip():
                            return hash_target_identifier(raw_val)
        except Exception:  # noqa: S110
            pass

    return None


def identity(
    request: Request,
    scope: Scope,
    target_subject: str | None = None,
) -> str | None:
    if scope in {Scope.IP, Scope.TARGET}:
        return client_ip(request) if scope == Scope.IP else target_subject

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
        limits = policy.limits if isinstance(policy.limits, tuple) else (policy.limits,)
        target_subject: str | None = None
        if any(lim.scope == Scope.TARGET for lim in limits):
            target_subject = await extract_target_identifier(request)

        for limit in limits:
            subject = identity(request, limit.scope, target_subject=target_subject)
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
