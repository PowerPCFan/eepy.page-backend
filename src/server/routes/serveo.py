import logging
import re
import time
from uuid import uuid4

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field, field_validator

from database.tables.domains import Domains
from database.tables.serveo import ServeoTable
from database.tables.sessions import Sessions
from dns_.dns import DNS
from dns_.exceptions import DNSException
from dns_.validation import Validation
from security.convert import Convert
from security.session import Session
from server.routes.domain import register_domain_record
from server.routes.models.domain import DomainType

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


class TunnelUpdate(BaseModel):
    local_port: int = Field(ge=1, le=65535)


class ServeoRoutes:
    def __init__(self, table: ServeoTable, users: object, sessions: Sessions, domains: Domains, dns: DNS) -> None:
        self.table = table
        self.domains = domains
        self.dns = dns
        self.dns_validation = Validation(domains, dns)
        converter.init_vars(users, sessions)  # pyright: ignore[reportArgumentType]
        self.router = APIRouter(prefix="/serveo")
        # there HAS to be a better way to do this, but IIWIW
        self.router.add_api_route(
            "/tunnels",
            self.list_tunnels,
            methods=["GET"],
            responses={460: {"description": "Invalid session"}},
        )
        self.router.add_api_route(
            "/tunnels",
            self.create_tunnel,
            methods=["POST"],
            responses={460: {"description": "Invalid session"}},
        )
        self.router.add_api_route(
            "/tunnels/{tunnel_id}",
            self.delete_tunnel,
            methods=["DELETE"],
            responses={460: {"description": "Invalid session"}},
        )
        self.router.add_api_route(
            "/tunnels/{tunnel_id}",
            self.update_tunnel,
            methods=["PUT"],
            responses={460: {"description": "Invalid session"}},
        )

    @staticmethod
    def _generate_ssh_command(hostname: str, port: int) -> str:
        return f"ssh -R {hostname}:80:localhost:{port} serveo.net"

    @Session.requires_auth
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

    @Session.requires_auth
    def create_tunnel(
        self,
        body: TunnelCreate,
        session: Session = Depends(converter.create),
    ) -> dict:
        hostname = Domains.canonical_full_domain_name(body.subdomain)
        auth_record = f"_serveo-authkey.{hostname}"
        target = "serveo.net"
        try:
            register_domain_record(
                self.domains,
                self.dns,
                self.dns_validation,
                DomainType(domain=hostname, type="CNAME", values=[target]),
                session,
            )
            session.user_cache_data["domains"] = self.domains.get_domains(session.username)
            register_domain_record(
                self.domains,
                self.dns,
                self.dns_validation,
                DomainType(domain=auth_record, type="TXT", values=[body.ssh_fingerprint]),
                session,
            )
        except (DNSException, HTTPException) as error:
            try:
                self.dns.delete_domain(hostname, "CNAME")
                self.dns.delete_domain(auth_record, "TXT")
                self.domains.delete_domain(session.username, hostname, "CNAME")
                self.domains.delete_domain(session.username, auth_record, "TXT")
            except DNSException:
                logger.exception("Failed to roll back Serveo DNS")
            if isinstance(error, HTTPException):
                raise
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

    @Session.requires_auth
    def update_tunnel(
        self,
        tunnel_id: str,
        body: TunnelUpdate,
        session: Session = Depends(converter.create),
    ) -> dict:
        tunnel = self.table.get_tunnel(session.username, tunnel_id)
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")

        hostname = tunnel["hostname"]
        old_auth_record = tunnel["serveo_auth_record"]
        new_auth_record = old_auth_record

        updated = {
            **tunnel,
            "serveo_auth_record": new_auth_record,
            "ssh_fingerprint": tunnel["ssh_fingerprint"],
            "subdomain": tunnel["subdomain"],
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

    @Session.requires_auth
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
        self.domains.delete_domain(session.username, tunnel["serveo_auth_record"], "TXT")
        self.table.remove_tunnel(tunnel_id, session.username)
