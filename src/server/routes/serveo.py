import logging
import re
import time
from typing import get_args
from uuid import uuid4

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field, field_validator

from database.exceptions import SubdomainError
from database.tables.domains import Domains
from database.tables.serveo import ServeoTable
from database.tables.sessions import Sessions
from dns_.dns import DNS
from dns_.exceptions import DNSException, DomainExistsError, ReservedDomainError
from dns_.types import AVAILABLE_TLDS
from dns_.validation import Validation
from security.convert import Convert
from security.session import Session

logger = logging.getLogger("eepy.page")
converter = Convert()


class TunnelCreate(BaseModel):
    subdomain: str
    local_port: int = Field(ge=1, le=65535)
    ssh_fingerprint: str = Field(min_length=10, max_length=200)

    @field_validator("ssh_fingerprint", mode="before")
    @classmethod
    def extract_ssh_fingerprint(cls, value: object) -> str:
        if not isinstance(value, str):
            msg = "SSH fingerprint must be text"
            raise ValueError(msg)  # noqa: TRY004

        match = re.search(r"SHA256:[A-Za-z0-9+/]+={0,2}", value)
        if not match:
            msg_0 = "Enter an SSH SHA256 fingerprint"
            raise ValueError(msg_0)

        return match.group(0)


class ServeoRoutes:
    def __init__(self, table: ServeoTable, users: object, sessions: Sessions, domains: Domains, dns: DNS) -> None:
        self.table = table
        self.domains = domains
        self.dns = dns
        self.dns_validation = Validation(domains, dns)
        converter.init_vars(users, sessions)  # pyright: ignore[reportArgumentType]
        self.router = APIRouter(prefix="/serveo")
        self.router.add_api_route("/tunnels", self.list_tunnels, methods=["GET"])
        self.router.add_api_route("/tunnels", self.create_tunnel, methods=["POST"])
        self.router.add_api_route("/tunnels/{tunnel_id}", self.delete_tunnel, methods=["DELETE"])
        self.router.add_api_route("/tunnels/{tunnel_id}", self.update_tunnel, methods=["PUT"])

    @staticmethod
    def _generate_ssh_command(hostname: str, port: int) -> str:
        return f"ssh -R {hostname}:80:localhost:{port} serveo.net"

    def list_tunnels(self, session: Session = Depends(converter.create)) -> dict:
        tunnels = self.table.tunnels(session.username)
        return {
            "connected": True,
            "tunnels": [
                {
                    **{k: v for k, v in tunnel.items() if k != "_id"},
                    "id": tunnel["_id"],
                    "command": tunnel["command"],
                }
                for tunnel in tunnels
            ],
        }

    def create_tunnel(  # noqa: C901, PLR0912
        self,
        body: TunnelCreate,
        session: Session = Depends(converter.create),
    ) -> dict:
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
        if self.table.tunnels(session.username):
            raise HTTPException(409, detail="You can only have one tunnel")
        auth_record = f"_serveo-authkey.{hostname}"
        target = "serveo.net"
        try:
            if not self.dns.register_domain(hostname, target, "CNAME", f"Serveo tunnel user: {session.username}"):
                msg = "DNS registration failed"
                raise DNSException(msg, {"domain": hostname})
            if not self.dns.register_domain(
                auth_record,
                body.ssh_fingerprint,
                "TXT",
                f"Serveo auth user: {session.username}",
            ):
                msg_0 = "Serveo authorization registration failed"
                raise DNSException(msg_0, {"domain": auth_record})
            self.domains.add_domain(
                session.username,
                hostname,
                {"type": "CNAME", "ip": [target], "registered": round(time.time())},
            )
        except DNSException:
            try:
                self.dns.delete_domain(hostname, "CNAME")
                self.dns.delete_domain(auth_record, "TXT")
            except DNSException:
                logger.exception("Failed to roll back Serveo DNS")
            raise HTTPException(502, detail="Failed to provision tunnel DNS")
        tunnel_document = {
            "_id": str(uuid4()),
            "user_id": session.username,
            "serveo_auth_record": auth_record,
            "ssh_fingerprint": body.ssh_fingerprint,
            "subdomain": body.subdomain,
            "hostname": hostname,
            "service": f"localhost:{body.local_port}",
            "local_port": body.local_port,
            "command": ServeoRoutes._generate_ssh_command(hostname, body.local_port),
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }
        self.table.save_tunnel(tunnel_document)
        tunnel_document["id"] = tunnel_document.pop("_id")
        return {
            "tunnel": tunnel_document,
            "command": ServeoRoutes._generate_ssh_command(hostname, body.local_port),
        }

    def update_tunnel(  # noqa: C901, PLR0912, PLR0915
        self,
        tunnel_id: str,
        body: TunnelCreate,
        session: Session = Depends(converter.create),
    ) -> dict:
        tunnel = self.table.get_tunnel(session.username, tunnel_id)
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")

        hostname = Domains.canonical_full_domain_name(body.subdomain)
        old_hostname = tunnel["hostname"]
        old_auth_record = tunnel["serveo_auth_record"]
        new_auth_record = f"_serveo-authkey.{hostname}"
        target = "serveo.net"

        if hostname != old_hostname:
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
                if self.dns.record_exists(hostname, "CNAME"):
                    available = False
            except ValueError:
                raise HTTPException(400, detail="Invalid domain name")
            except SubdomainError as error:
                raise HTTPException(
                    403,
                    detail=f"You need to own {error.required_domain} before registering {hostname}",
                )
            except (DNSException, DomainExistsError, ReservedDomainError):
                raise HTTPException(409, detail="Domain is unavailable")
            if not available:
                raise HTTPException(409, detail="Domain is unavailable")
            try:
                self.dns.register_domain(hostname, target, "CNAME", f"Serveo tunnel user: {session.username}")
                self.dns.register_domain(
                    new_auth_record,
                    body.ssh_fingerprint,
                    "TXT",
                    f"Serveo auth user: {session.username}",
                )
                self.domains.add_domain(
                    session.username,
                    hostname,
                    {"type": "CNAME", "ip": [target], "registered": round(time.time())},
                )
                self.dns.delete_domain(old_hostname, "CNAME")
                self.dns.delete_domain(old_auth_record, "TXT")
                self.domains.delete_domain(session.username, old_hostname, "CNAME")
            except DNSException:
                raise HTTPException(502, detail="Failed to update tunnel DNS")
        else:
            try:
                self.dns.modify_domain(
                    values=[body.ssh_fingerprint],
                    type="TXT",
                    old_type="TXT",
                    domain=new_auth_record,
                    user_id=session.username,
                )
            except DNSException:
                raise HTTPException(502, detail="Failed to update tunnel authorization")

        updated = {
            **tunnel,
            "serveo_auth_record": new_auth_record,
            "ssh_fingerprint": body.ssh_fingerprint,
            "subdomain": body.subdomain,
            "hostname": hostname,
            "service": f"localhost:{body.local_port}",
            "local_port": body.local_port,
            "command": ServeoRoutes._generate_ssh_command(hostname, body.local_port),
            "updated_at": int(time.time()),
        }
        self.table.replace_tunnel(tunnel_id, session.username, updated)
        updated.pop("_id", None)
        command = ServeoRoutes._generate_ssh_command(hostname, body.local_port)
        return {"tunnel": {**updated, "id": tunnel_id, "command": command}, "command": command}

    def delete_tunnel(self, tunnel_id: str, session: Session = Depends(converter.create)) -> None:
        tunnel = self.table.get_tunnel(session.username, tunnel_id)
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")
        if not self.dns.delete_domain(tunnel["hostname"], "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but DNS cleanup failed")
        if not self.dns.delete_domain(tunnel["serveo_auth_record"], "TXT"):
            raise HTTPException(502, detail="Tunnel deleted but Serveo authorization cleanup failed")
        if not self.domains.delete_domain(session.username, tunnel["hostname"], "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but domain cleanup failed")
        self.table.remove_tunnel(tunnel_id, session.username)
