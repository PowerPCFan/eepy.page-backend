import ast
import os
from collections.abc import Generator
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from security import rate_limit
from security.rate_limit import Limit, Policy, RateLimitMiddleware, RedisStore, Scope, client_ip
from starlette.requests import Request


@pytest.fixture
def redis_store() -> Generator[RedisStore, None, None]:
    store = RedisStore(os.getenv("REDIS_TEST_URL", "redis://localhost:6379/15"))
    store.client.flushdb()
    yield store
    store.client.flushdb()
    store.client.close()


def test_socket_client_ip_is_used_without_caddy_header() -> None:
    """Falls back to the connection peer when no forwarded address exists."""
    assert client_ip(Request({
        "type": "http",
        "headers": [],
        "client": (
            "198.51.100.10",
            50000,
        ),
    })) == "198.51.100.10"


ROUTE_PREFIXES = {
    "admin.py": "/admin",
    "api.py": "/api",
    "auth.py": "",
    "domain.py": "/domain",
    "invite.py": "/invite",
    "kofi.py": "/kofi",
    "serveo.py": "/serveo",
    "user.py": "",
}


def registered_routes() -> list[tuple[str, str]]:
    routes = [("GET", "/status")]
    routes_directory = Path(__file__).parents[1] / "server" / "routes"
    for file_name, prefix in ROUTE_PREFIXES.items():
        tree = ast.parse((routes_directory / file_name).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_api_route" or not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            methods = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "methods"),
                None,
            )
            if not isinstance(methods, ast.List):
                continue
            for method in methods.elts:
                if isinstance(method, ast.Constant) and isinstance(method.value, str):
                    routes.append((method.value, f"{prefix}{node.args[0].value}"))
    return routes


def test_every_registered_endpoint_is_rate_limited(monkeypatch, redis_store: RedisStore) -> None:
    """Blocks a second request to every registered route without invoking production handlers."""
    for name, policy in rate_limit.POLICIES.items():
        monkeypatch.setitem(rate_limit.POLICIES, name, Policy(name, tuple(Limit(
            max_requests=1,
            time_window=60,
            scope=limit.scope,
        ) for limit in (
            policy.limits
            if isinstance(policy.limits, tuple)
            else (policy.limits,)
        ))))

    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
    def handler(path: str) -> dict[str, str]:
        return {"path": path}

    app.add_middleware(RateLimitMiddleware, store=redis_store)
    with TestClient(app) as client:
        for index, (method, path) in enumerate(registered_routes(), start=1):
            concrete_path = path.replace("{tunnel_id}", "test-tunnel")
            headers = {
                "X-Forwarded-For": f"198.51.100.{index}",
                "Authorization": f"Bearer test-credential-{index}",
            }
            assert client.request(method, concrete_path, headers=headers).status_code == 200
            assert client.request(method, concrete_path, headers=headers).status_code == 429


def test_limit_exhaustion_returns_retry_after(redis_store: RedisStore) -> None:
    """Returns a standard rate-limit response after the login policy is exhausted."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/login")
    def login() -> dict[str, bool]:
        return {"ok": True}

    policy = rate_limit.get_policy("POST", "/login")
    limits = policy.limits if isinstance(policy.limits, tuple) else (policy.limits,)
    ip_limit = next(limit for limit in limits if limit.scope == Scope.IP)

    with TestClient(app) as client:
        for _ in range(ip_limit.max_requests):
            assert client.post("/login").status_code == 200
        limited = client.post("/login")

    assert limited.status_code == 429
    assert limited.json()["detail"] == "Rate limit exceeded"
    assert int(limited.headers["Retry-After"]) > 0


def test_recovery_sending_is_limited_by_ip_and_authenticated_account(monkeypatch, redis_store: RedisStore) -> None:
    """Prevents recovery-email spam by source IP and target account over a day."""
    policy = Policy(
        "recovery",
        (
            Limit(max_requests=3, time_window=3600, scope=Scope.IP),
            Limit(max_requests=5, time_window=86400, scope=Scope.ACCOUNT),
        ),
    )
    monkeypatch.setitem(rate_limit.POLICIES, policy.name, policy)
    monkeypatch.setattr(rate_limit.Session, "access_token_subject", lambda token: token)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/recovery/send")
    def send_recovery(username: str) -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        for index in range(5):
            response = client.post(
                "/recovery/send",
                headers={
                    "Authorization": "Bearer target-account",
                    "X-Forwarded-For": f"198.51.100.{index}",
                },
            )
            assert response.status_code == 200

        target_limited = client.post(
            "/recovery/send",
            headers={"Authorization": "Bearer target-account", "X-Forwarded-For": "198.51.100.10"},
        )
        for account in ("another-account", "third-account"):
            response = client.post(
                "/recovery/send",
                headers={"Authorization": f"Bearer {account}", "X-Forwarded-For": "198.51.100.0"},
            )
            assert response.status_code == 200
        ip_limited = client.post(
            "/recovery/send",
            headers={"Authorization": "Bearer fourth-account", "X-Forwarded-For": "198.51.100.0"},
        )

    assert target_limited.status_code == 429
    assert ip_limited.status_code == 429


def test_account_limits_span_multiple_sessions(monkeypatch, redis_store: RedisStore) -> None:
    """Shares account limits across separately issued access tokens for the same account."""
    policy = Policy("account", Limit(max_requests=1, time_window=60, scope=Scope.ACCOUNT))
    monkeypatch.setitem(rate_limit.POLICIES, policy.name, policy)
    monkeypatch.setitem(rate_limit.ROUTE_POLICIES, (rate_limit.Method.POST, "/account"), policy.name)
    monkeypatch.setattr(rate_limit.Session, "access_token_subject", lambda token: "account-id")
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/account")
    def account_action() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        first = client.post("/account", headers={"Authorization": "Bearer first-session"})
        second = client.post("/account", headers={"Authorization": "Bearer second-session"})

    assert first.status_code == 200
    assert second.status_code == 429


def test_redis_failure_returns_server_error(monkeypatch, redis_store: RedisStore) -> None:
    """Does not bypass rate limiting when Redis becomes unavailable after startup."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.get("/read")
    def read() -> dict[str, bool]:
        return {"ok": True}

    def unavailable(key: str, seconds: int) -> tuple[int, int]:
        raise RuntimeError("Redis is unavailable")

    monkeypatch.setattr(redis_store, "consume", unavailable)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/read")

    assert response.status_code == 500


def test_credential_limits_are_partitioned(monkeypatch, redis_store: RedisStore) -> None:
    policy = Policy("api_mutation", (Limit(max_requests=1, time_window=60, scope=Scope.CREDENTIAL),))
    monkeypatch.setitem(__import__("security.rate_limit", fromlist=["ROUTE_POLICIES"]).ROUTE_POLICIES, ("POST", "/api/domain"), policy.name)
    monkeypatch.setitem(__import__("security.rate_limit", fromlist=["POLICIES"]).POLICIES, policy.name, policy)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/api/domain")
    def mutate() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        assert client.post("/api/domain", headers={"X-Auth-Token": "first"}).status_code == 200
        assert client.post("/api/domain", headers={"X-Auth-Token": "second"}).status_code == 200
        assert client.post("/api/domain", headers={"X-Auth-Token": "first"}).status_code == 429


def test_malformed_authorization_uses_the_ip_limit(monkeypatch, redis_store: RedisStore) -> None:
    """Leaves malformed credentials for the auth layer while applying an IP backstop."""
    policy = Policy("malformed", (Limit(max_requests=1, time_window=60, scope=Scope.CREDENTIAL),))
    monkeypatch.setitem(rate_limit.POLICIES, policy.name, policy)
    monkeypatch.setitem(rate_limit.ROUTE_POLICIES, ("POST", "/malformed"), policy.name)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/malformed")
    def malformed() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        headers = {"Authorization": "not-a-bearer-token"}
        assert client.post("/malformed", headers=headers).status_code == 200
        assert client.post("/malformed", headers=headers).status_code == 429


def test_multiple_limits_must_all_allow_the_request(monkeypatch, redis_store: RedisStore) -> None:
    """Enforces a short burst limit even when the longer limit still permits requests."""
    policy = Policy("stacked", (Limit(max_requests=10, time_window=3600, scope=Scope.IP), Limit(max_requests=1, time_window=3, scope=Scope.IP)))
    monkeypatch.setitem(rate_limit.POLICIES, policy.name, policy)
    monkeypatch.setitem(rate_limit.ROUTE_POLICIES, ("POST", "/stacked"), policy.name)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, store=redis_store)

    @app.post("/stacked")
    def stacked() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app) as client:
        assert client.post("/stacked").status_code == 200
        assert client.post("/stacked").status_code == 429
