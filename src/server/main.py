import datetime as dt
import logging
import sys
import threading
import time
from collections.abc import Awaitable, Callable

import sentry_sdk
from dotenv import load_dotenv
from eepy_page_i18n import resolve_request_locale, set_current_locale
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.env import Environment
from database.cleanup import start_expired_cleanup_loop
from database.session import create_db_engine, set_engine
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.invitation import Invites
from database.tables.reward_codes import Rewards
from database.tables.serveo import ServeoTable
from database.tables.sessions import Sessions
from database.tables.status import Status
from database.tables.users import Users
from dns_.dns import DNS
from mail.email import Email
from security.admin import Admin as AdminTools
from security.api import ApiError, ApiPermissionError, ApiRangeError
from security.encryption import Encryption
from security.rate_limit import RateLimitMiddleware, create_store
from security.session import SessionError, SessionPermissonError
from server.routes.admin import Admin
from server.routes.api import API
from server.routes.auth import Auth
from server.routes.domain import Domain
from server.routes.invite import Invite
from server.routes.kofi import Kofi
from server.routes.serveo import ServeoRoutes
from server.routes.user import User

start = time.time()
Environment.set_value("START_ELAPSED", str(round(time.time() - start, 2)))
Environment.set_value("STARTED_AT", str(start))

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(name)s] %(levelname)s: [%(filename)s:%(funcName)s] %(message)s",
    datefmt="%d/%m/%Y %H.%M.%S",
    stream=sys.stdout,
)

logger: logging.Logger = logging.getLogger("eepy.page")
logger.handlers = []

logger.info("Logger init")

if not load_dotenv():
    logger.warning("Failed to load .env file")

tags_metadata: list[dict[str, str]] = [
    {"name": "domains", "description": "Viewing, creating, and managing domains"},
    {"name": "account", "description": "Getting account data, changing settings, signing up, logging in"},
    {"name": "invite", "description": "Viewing, creating, and managing invites"},
    {"name": "api", "description": "Routes that can be used with the public API"},
]

debug = Environment.debug_mode()

sentry_sdk.init(
    dsn=Environment.sentry_dsn(),
    environment=("development" if debug else "production"),
    send_default_pii=True,
)

app = FastAPI(docs_url=None, redoc_url=None)
app.state.safe_domains = [
    "https://eepy.page",
    "https://www.eepy.page",
    "https://beta.eepy.page",
    "https://alpha.eepy.page",
    "https://development.eepy.page",
    "https://canary.eepy.page",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(RateLimitMiddleware, store=create_store())
app.add_middleware(
    CORSMiddleware,
    allow_origins=app.state.safe_domains,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Auth-Error"],
)


@app.middleware("http")
async def locale_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    set_current_locale(resolve_request_locale(request.headers))
    return await call_next(request)


engine = create_db_engine(Environment.postgres_url())
set_engine(engine)


class DatabaseRepositories:
    def __init__(self) -> None:
        self.users: Users = Users(engine)
        self.rewards: Rewards = Rewards(engine, self.users)
        self.sessions: Sessions = Sessions(engine)
        self.invites: Invites = Invites(engine)
        self.codes: Codes = Codes(engine)
        self.domains: Domains = Domains(engine)
        self.dns: DNS = DNS(self.domains)
        self.tunnels: ServeoTable = ServeoTable(engine)
        self.status: Status = Status(engine)

        threading.Thread(target=self.users.migrate_all_users, daemon=True).start()
        threading.Thread(target=self.users.start_unverified_purge_loop, daemon=True).start()
        threading.Thread(target=start_expired_cleanup_loop, args=(engine,), daemon=True).start()


v = DatabaseRepositories()

domain_instance = Domain(v.users, v.sessions, v.domains, v.dns)
app.include_router(domain_instance.router, include_in_schema=False)

app.include_router(API(v.users, v.domains, v.dns, v.sessions).router)
app.include_router(
    ServeoRoutes(v.tunnels, v.users, v.sessions, v.domains, v.dns).router,
    include_in_schema=False,
)
app.include_router(Invite(v.users, v.sessions, v.invites).router, include_in_schema=False)

email: Email = Email(v.codes, v.users, Encryption(Environment.enc_key()))
app.include_router(
    User(
        table=v.users,
        session_table=v.sessions,
        invite_table=v.invites,
        email=email,
        codes=v.codes,
        dns=v.dns,
        rewards=v.rewards,
    ).router,
    include_in_schema=False,
)
app.include_router(
    Auth(v.users, v.sessions, v.invites, email, v.dns).router,
    include_in_schema=False,
)
app.include_router(Kofi(email, v.rewards).router, include_in_schema=False)

app.include_router(
    Admin(
        v.users,
        v.sessions,
        v.status,
        AdminTools(
            v.users,
            v.sessions,
            v.domains,
            v.dns,
            email,
        ),
    ).router,
    include_in_schema=False,
)


@app.get("/status")
async def status() -> JSONResponse:
    content = {
        "started_at": dt.datetime.fromtimestamp(
            Environment.started_at(),
            dt.UTC,
        ).isoformat(),
        "start_elapsed": f"{Environment.start_elapsed()}s",
    }

    current_status = v.status.get()
    if current_status is not None:
        content["message"] = current_status["message"]

    return JSONResponse(status_code=200, content=content)


@app.exception_handler(SessionError)
async def session_except_handler(_request: Request, e: Exception) -> JSONResponse:
    logger.warning(e.args)
    return JSONResponse(status_code=460, content={"message": "Invalid session"})


@app.exception_handler(SessionPermissonError)
async def session_permission_except_handler(_request: Request, _e: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=461,
        content={"message": "You lack the necessary permissions to run this action"},
    )


@app.exception_handler(ApiError)
async def api_except_handler(_request: Request, e: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=460,
        content={"message": "Invalid API key", "detail": e.args},
    )


@app.exception_handler(ApiRangeError)
async def api_range_except_handler(_request: Request, e: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=461,
        content={
            "message": "API key cannot do operations on requested domain",
            "detail": e.args,
        },
    )


@app.exception_handler(ApiPermissionError)
async def api_permission_except_handler(_request: Request, e: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=462,
        content={
            "message": "API key does not have the necessary permissions to perform this action",
            "detail": e.args,
        },
    )


# TODO: fix deprecated event, also make this less janky
@app.on_event("shutdown")
async def _shutdown_event() -> None:
    logger.info("Application shutdown: disposing database engine and flushing Sentry")
    try:
        engine.dispose()
    except Exception:
        logger.exception("Error disposing database engine")

    try:
        sentry_sdk.flush(timeout=5)
    except Exception:
        logger.exception("Error flushing Sentry")
