import hashlib
import logging
import os
import secrets
import time
from typing import get_args
from urllib.parse import urlencode
from uuid import uuid4

import requests
from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, HttpUrl

from database.exceptions import SubdomainError
from database.tables.cloudflare import Cloudflare
from database.tables.domains import Domains
from database.tables.sessions import Sessions
from dns_.dns import DNS, ConflictingDomain
from dns_.exceptions import DNSException, DomainExistsError, ReservedDomainError
from dns_.types import AVAILABLE_TLDS
from dns_.validation import Validation
from security.convert import Convert
from security.encryption import Encryption
from security.session import Session

logger = logging.getLogger("eepy.page")
converter = Convert()

SCOPES = [
    "teams-connector-cloudflared.monitoring",
    "teams-connector-cloudflared.read",
    "teams-connector-cloudflared.write",
    # "teams-connectors.read",
    # "teams-connectors.write",
    "argotunnel.read",
    "argotunnel.write",
    "memberships.read",
]


class TunnelCreate(BaseModel):
    subdomain: str
    service: HttpUrl


class CloudflareRoutes:
    def __init__(self, table: Cloudflare, users: object, sessions: Sessions, domains: Domains, dns: DNS) -> None:
        self.table = table
        self.domains = domains
        self.dns = dns
        self.dns_validation = Validation(domains, dns)
        converter.init_vars(users, sessions)  # type: ignore[arg-type]
        self.encryption = Encryption(os.getenv("ENC_KEY"))
        self.router = APIRouter(prefix="/cloudflare")
        self.router.add_api_route("/connect", self.connect, methods=["POST"])
        self.router.add_api_route("/callback", self.callback, methods=["GET"])
        self.router.add_api_route("/disconnect", self.disconnect, methods=["DELETE"])
        self.router.add_api_route("/tunnels", self.list_tunnels, methods=["GET"])
        self.router.add_api_route("/tunnels", self.create_tunnel, methods=["POST"])
        self.router.add_api_route("/tunnels/{tunnel_id}", self.delete_tunnel, methods=["DELETE"])
        self.router.add_api_route("/tunnels/{tunnel_id}/token", self.tunnel_token, methods=["POST"])

    def _require_connection(self, user_id: str) -> dict:
        connection = self.table.connection(user_id)
        if not connection or not connection.get("access_token") or not connection.get("cloudflare_account_id"):
            raise HTTPException(412, detail="Cloudflare is not connected")
        return connection  # pyright: ignore[reportReturnType]

    def _request(self, method: str, path: str, token: str, **kwargs: object) -> dict:
        response = requests.request(
            method,
            f"https://api.cloudflare.com/client/v4{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15,
            **kwargs,  # pyright: ignore[reportArgumentType]
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if not response.ok or not payload.get("success", False):
            logger.warning("Cloudflare API request failed: %s %s", method, path)
            raise HTTPException(502, detail="Cloudflare API request failed")
        return payload.get("result", {})

    def connect(self, session: Session = Depends(converter.create)) -> JSONResponse:
        state = secrets.token_urlsafe(32)
        self.table.save_connection(session.username, {"oauth_state_hash": hashlib.sha256(state.encode()).hexdigest()})
        params = {
            "response_type": "code",
            "client_id": os.getenv("CLOUDFLARE_OAUTH_CLIENT_ID", ""),
            "redirect_uri": os.getenv("CLOUDFLARE_OAUTH_REDIRECT_URI", ""),
            "scope": " ".join(SCOPES),
            "state": state,
        }
        return JSONResponse({"url": "https://dash.cloudflare.com/oauth2/auth?" + urlencode(params)})

    def callback(self, code: str, state: str) -> RedirectResponse:
        connection = self.table.find_item({"oauth_state_hash": hashlib.sha256(state.encode()).hexdigest()})
        if not connection:
            raise HTTPException(400, detail="Invalid OAuth state")
        token_response = requests.post(
            "https://dash.cloudflare.com/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": os.getenv("CLOUDFLARE_OAUTH_CLIENT_ID", ""),
                "client_secret": os.getenv("CLOUDFLARE_OAUTH_CLIENT_SECRET", ""),
                "redirect_uri": os.getenv("CLOUDFLARE_OAUTH_REDIRECT_URI", ""),
            },
            timeout=15,
        )
        if not token_response.ok:
            raise HTTPException(502, detail="Cloudflare OAuth failed")
        token = token_response.json()
        access_token = token.get("access_token")
        if not access_token:
            raise HTTPException(502, detail="Cloudflare OAuth returned no access token")
        memberships = self._request("GET", "/memberships", access_token)
        membership = memberships[0] if isinstance(memberships, list) and memberships else None
        account = membership.get("account") if isinstance(membership, dict) else None
        if not account or not account.get("id"):
            raise HTTPException(400, detail="No Cloudflare account available")
        self.table.save_connection(
            connection["user_id"],
            {
                "cloudflare_account_id": account["id"],
                "access_token": self.encryption.encrypt(access_token),
                "refresh_token": self.encryption.encrypt(token["refresh_token"])
                if token.get("refresh_token")
                else None,
                "expires_at": int(time.time()) + int(token.get("expires_in", 0)),
                "oauth_state_hash": None,
            },
        )
        frontend = os.getenv("CLOUDFLARE_FRONTEND_REDIRECT", "https://www.eepy.page/dashboard/tunneling")
        return RedirectResponse(frontend + "?cloudflare=connected")

    def disconnect(self, session: Session = Depends(converter.create)) -> None:
        connection = self._require_connection(session.username)
        token = self.encryption.decrypt(connection["access_token"])
        try:
            requests.post("https://dash.cloudflare.com/oauth2/revoke", data={"token": token}, timeout=15)
        finally:
            self.table.delete_connection(session.username)

    def list_tunnels(self, session: Session = Depends(converter.create)) -> dict:
        connection = self.table.connection(session.username)
        tunnels = self.table.tunnels(session.username)
        return {
            "connected": bool(connection and connection.get("cloudflare_account_id")),
            "account_id": connection.get("cloudflare_account_id") if connection else None,
            "tunnels": [{**{k: v for k, v in tunnel.items() if k != "_id"}, "id": tunnel["_id"]} for tunnel in tunnels],  # pyright: ignore[reportTypedDictNotRequiredAccess]
        }

    def create_tunnel(  # noqa: C901, PLR0912, PLR0915
        self,
        body: TunnelCreate,
        session: Session = Depends(converter.create),
    ) -> dict:
        connection = self._require_connection(session.username)
        hostname = Domains.canonical_full_domain_name(body.subdomain)
        domains = Domains.normalize_domains(session.user_cache_data.get("domains", []))
        user_data = dict(session.user_cache_data)
        user_data["domains"] = domains
        if not hostname.endswith(tuple(f".{tld}" for tld in get_args(AVAILABLE_TLDS))):
            raise HTTPException(412, detail="Tunnel domain uses an unsupported TLD")
        _, tld = self.domains.separate_domain_into_parts(hostname)
        if tld not in session.user_cache_data.get("owned-tlds", ["eepy.page"]):
            raise HTTPException(401, detail=f"You must purchase {tld} before registering this domain")
        can_register = Validation.can_user_register(hostname, user_data)  # type: ignore[arg-type]
        if not can_register.success:
            raise HTTPException(405, detail=can_register.comment)
        try:
            available = self.dns_validation.is_free(
                hostname,
                "CNAME",
                domains,  # pyright: ignore[reportArgumentType]
                user_id=session.username,
                user_is_admin=session.user_cache_data.get("permissions", {}).get("admin", False),
            )
        except ValueError:
            raise HTTPException(400, detail="Invalid domain name")
        except SubdomainError as error:
            raise HTTPException(403, detail=f"You need to own {error.required_domain} before registering {hostname}")
        except (DomainExistsError, ReservedDomainError):
            raise HTTPException(409, detail="Domain is unavailable")
        if not available:
            raise HTTPException(409, detail="Domain is already registered or unavailable")
        try:
            if self.dns.record_exists(hostname, "CNAME"):
                raise HTTPException(409, detail="Domain is already registered")
        except DNSException:
            raise HTTPException(500, detail="DNS availability check failed")
        if self.table.find_item({"user_id": session.username, "hostname": hostname}):
            raise HTTPException(409, detail="A tunnel already uses this hostname")
        token = self.encryption.decrypt(connection["access_token"])
        account_id = connection["cloudflare_account_id"]
        tunnel = self._request(
            "POST",
            f"/accounts/{account_id}/cfd_tunnel",
            token,
            json={"name": hostname, "config_src": "cloudflare"},
        )
        tunnel_id = tunnel.get("id")
        if not tunnel_id:
            raise HTTPException(502, detail="Cloudflare did not return a tunnel id")
        try:
            self._request(
                "PUT",
                f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                token,
                json={
                    "config": {
                        "ingress": [
                            {"hostname": hostname, "service": str(body.service)},
                            {"service": "http_status:404"},
                        ],
                    },
                },
            )
            target = f"{tunnel_id}.cfargotunnel.com"
            try:
                if not self.dns.register_domain(
                    hostname,
                    target,
                    "CNAME",
                    f"Registered through Cloudflare Tunnel user: {session.username}",
                ):
                    msg = "DNS registration failed"
                    raise DNSException(msg, {"domain": hostname})
            except ConflictingDomain:
                raise HTTPException(409, detail="Domain is already registered")
            self.domains.add_domain(
                session.username,
                hostname,
                {"type": "CNAME", "ip": [target], "registered": round(time.time())},
            )
        except HTTPException as error:
            try:
                self._request("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}", token)
            except HTTPException:
                logger.exception("Failed to roll back Cloudflare tunnel")
            raise error  # noqa: TRY201
        except DNSException:
            try:
                self._request("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}", token)
            except HTTPException:
                logger.exception("Failed to roll back Cloudflare tunnel")
            raise HTTPException(502, detail="Failed to provision tunnel DNS")
        tunnel_document = {
            "_id": str(uuid4()),
            "user_id": session.username,
            "cloudflare_tunnel_id": tunnel_id,
            "cloudflare_account_id": account_id,
            "subdomain": body.subdomain,
            "hostname": hostname,
            "service": str(body.service),
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }
        self.table.insert_document(tunnel_document)
        tunnel_document["id"] = tunnel_document.pop("_id")
        return {
            "tunnel": tunnel_document,
            "token": self._request("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token", token),
        }

    def delete_tunnel(self, tunnel_id: str, session: Session = Depends(converter.create)) -> None:
        connection = self._require_connection(session.username)
        tunnel = self.table.find_item({"_id": tunnel_id, "user_id": session.username})
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")
        token = self.encryption.decrypt(connection["access_token"])
        self._request(
            "DELETE",
            f"/accounts/{tunnel['cloudflare_account_id']}/cfd_tunnel/{tunnel['cloudflare_tunnel_id']}",
            token,
        )
        if not self.dns.delete_domain(tunnel["hostname"], "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but DNS cleanup failed")
        if not self.domains.delete_domain(session.username, tunnel["hostname"], "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but domain cleanup failed")
        self.table.delete_document({"_id": tunnel_id, "user_id": session.username})

    def tunnel_token(self, tunnel_id: str, session: Session = Depends(converter.create)) -> dict:
        connection = self._require_connection(session.username)
        tunnel = self.table.find_item({"_id": tunnel_id, "user_id": session.username})
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")
        token = self.encryption.decrypt(connection["access_token"])
        return {
            "token": self._request(
                "GET",
                f"/accounts/{tunnel['cloudflare_account_id']}/cfd_tunnel/{tunnel['cloudflare_tunnel_id']}/token",
                token,
            ),
        }
