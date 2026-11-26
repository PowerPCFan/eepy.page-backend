import logging
import time
from uuid import uuid4

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException

from database.models import ServeoTunnel
from database.tables.domains import Domains
from database.tables.serveo import ServeoTable
from database.tables.sessions import Sessions
from dns_.dns import DNS
from dns_.exceptions import DNSException
from dns_.validation import Validation
from security.convert import Convert
from security.session import Session
from server.models.domain import DomainType
from server.models.serveo import ServeoRecord, TunnelCreate, TunnelUpdate
from server.routes.domain import register_domain_record

logger = logging.getLogger("eepy.page")
converter = Convert()


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
        tunnels = self.table.tunnels(session.user_id)
        return {
            "connected": True,
            "tunnels": [ServeoRecord.model_validate(tunnel).model_dump() for tunnel in tunnels],
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
        cname_created = False
        txt_created = False
        try:
            register_domain_record(
                self.domains,
                self.dns,
                self.dns_validation,
                DomainType(domain=hostname, type="CNAME", values=[target]),
                session,
            )
            cname_created = True
            session.user.domains = self.domains.get_domains(session.user_id)
            register_domain_record(
                self.domains,
                self.dns,
                self.dns_validation,
                DomainType(domain=auth_record, type="TXT", values=[body.ssh_fingerprint]),
                session,
            )
            txt_created = True
        except (DNSException, HTTPException) as error:
            try:
                if cname_created:
                    self.dns.delete_domain(hostname, "CNAME")
                    self.domains.delete_domain(session.user_id, hostname, "CNAME")
                if txt_created:
                    self.dns.delete_domain(auth_record, "TXT")
                    self.domains.delete_domain(session.user_id, auth_record, "TXT")
            except DNSException:
                logger.exception("Failed to roll back Serveo DNS")
            if isinstance(error, HTTPException):
                raise
            raise HTTPException(502, detail="Failed to provision tunnel DNS")
        now_ts = int(time.time())
        command = ServeoRoutes._generate_ssh_command(hostname, body.local_port)
        tunnel = ServeoTunnel(
            id=str(uuid4()),
            user_id=session.user_id,
            serveo_auth_record=auth_record,
            ssh_fingerprint=body.ssh_fingerprint,
            subdomain=body.subdomain,
            hostname=hostname,
            service=f"localhost:{body.local_port}",
            local_port=body.local_port,
            command=command,
            created_at=now_ts,
            updated_at=now_ts,
        )
        self.table.save_tunnel(tunnel)
        return {
            "tunnel": ServeoRecord.model_validate(tunnel).model_dump(),
            "command": command,
        }

    @Session.requires_auth
    def update_tunnel(
        self,
        tunnel_id: str,
        body: TunnelUpdate,
        session: Session = Depends(converter.create),
    ) -> dict:
        tunnel = self.table.get_tunnel(session.user_id, tunnel_id)
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")

        command = ServeoRoutes._generate_ssh_command(tunnel.hostname, body.local_port)
        updated = self.table.update_tunnel_port(
            tunnel_id,
            session.user_id,
            local_port=body.local_port,
            command=command,
            updated_at=int(time.time()),
        )
        if updated is None:
            raise HTTPException(404, detail="Tunnel not found")
        return {
            "tunnel": ServeoRecord.model_validate(updated).model_dump(),
            "command": command,
        }

    @Session.requires_auth
    def delete_tunnel(self, tunnel_id: str, session: Session = Depends(converter.create)) -> None:
        tunnel = self.table.get_tunnel(session.user_id, tunnel_id)
        if not tunnel:
            raise HTTPException(404, detail="Tunnel not found")
        if not self.dns.delete_domain(tunnel.hostname, "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but DNS cleanup failed")
        if not self.dns.delete_domain(tunnel.serveo_auth_record, "TXT"):
            raise HTTPException(502, detail="Tunnel deleted but Serveo authorization cleanup failed")
        if not self.domains.delete_domain(session.user_id, tunnel.hostname, "CNAME"):
            raise HTTPException(502, detail="Tunnel deleted but domain cleanup failed")
        self.domains.delete_domain(session.user_id, tunnel.serveo_auth_record, "TXT")
        self.table.remove_tunnel(tunnel_id, session.user_id)
