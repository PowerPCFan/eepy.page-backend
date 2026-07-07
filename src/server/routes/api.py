import logging
import time

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException

from database.exceptions import SubdomainError, UserNotExistError
from database.tables.domains import DomainRecord
from database.tables.domains import Domains as DomainTable
from database.tables.sessions import Sessions as SessionTable
from database.tables.users import UserPageType
from database.tables.users import Users as UsersTable
from dns_.dns import DNS
from dns_.exceptions import DNSException, DomainExistsError
from dns_.validation import Validation
from security.api import Api, ApiPermission
from security.convert import ConvertAPI
from server.routes.models.domain import DomainType

converter: ConvertAPI = ConvertAPI()
logger: logging.Logger = logging.getLogger("eepy.page")


class API:
    def __init__(
        self,
        table: UsersTable,
        domains: DomainTable,
        dns: DNS,
        session_table: SessionTable,
    ) -> None:
        converter.init_vars(table)

        self.table: UsersTable = table
        self.dns: DNS = dns
        self.domains: DomainTable = domains
        self.dns_validation: Validation = Validation(domains, dns)
        self.sessions = session_table

        self.router = APIRouter(prefix="/api")

        self.router.add_api_route(
            "/domain",
            self.register,
            methods=["POST"],
            status_code=200,
            responses={
                200: {"description": "Domain created"},
                400: {"description": "Invalid domain name"},
                403: {
                    "description": "Domain missing for subdomain (e.g: a.b.eepy.page needs b.eepy.page registered)",
                },
                405: {"description": "Domain limit exceeded"},
                409: {"description": "Domain already in use"},
                412: {"description": "Invalid DNS record type"},
                460: {"description": "Invalid API key"},
                462: {"description": "Invalid API key permissions ('register' needed)"},
            },
            tags=["api", "domain"],
        )

        self.router.add_api_route(
            "/domain",
            self.modify,
            methods=["PATCH"],
            status_code=200,
            responses={
                200: {"description": "Domain modified"},
                403: {"description": "User does not own domain"},
                412: {"description": "Invalid record name or value"},
                460: {"description": "Invalid API key"},
                461: {
                    "description": "API key cannot do operations on requested domain",
                },
                462: {"description": "Invalid API key permissions ('content' needed)"},
            },
            tags=["api", "domain"],
        )

        self.router.add_api_route(
            "/domain/available",
            self.is_available,
            methods=["GET"],
            status_code=200,
            description="Check whether a domain is available. No authentication required",
            responses={
                200: {"description": "Domain is available"},
                409: {"description": "Domain is not available"},
            },
            tags=["api", "domain"],
        )

        self.router.add_api_route(
            "/domains",
            self.get_domains,
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "Retrieved domains"},
                460: {"description": "Invalid API"},
                461: {"description": "Invalid API permissions"},
            },
            tags=["api", "domain"],
        )

        self.router.add_api_route(
            "/domain",
            self.delete,
            methods=["DELETE"],
            status_code=200,
            responses={
                200: {"description": "Domain deleted successfully"},
                403: {"description": "Domain does not exist, or user does not own it."},
                404: {
                    "description": "Domain type couldn't be fetched, specify the type using the query parameter `type`",
                },
                460: {"description": "Invalid session"},
                461: {
                    "description": "API key cannot do operations on requested domain",
                },
                462: {"description": "Invalid API key permissions ('delete' needed)"},
            },
            tags=["api", "domain"],
        )

        self.router.add_api_route(
            "/intents",
            self.get_key_intents,
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "Returns a list of intents which the key has"},
            },
        )

        self.router.add_api_route(
            "/user",
            self.get_user_profile,
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "User data retrieved"},
                404: {"description": "Failed to load user data"},
                462: {"description": "API key cannot do this ('userdetails' needed)"},
            },
            tags=["api", "user"],
        )

        logger.info("Initialized")

    @Api.requires_auth
    @Api.requires_permission("register")
    def register(self, body: DomainType, api: Api = Depends(converter.create)) -> None:
        can_user_register = self.dns_validation.can_user_register(
            body.domain,
            api.user_cache_data,
        )

        if not can_user_register.success:
            raise HTTPException(status_code=405, detail=can_user_register.comment)

        try:
            is_domain_available: bool = self.dns_validation.is_free(
                body.domain,
                body.type,
                api.user_cache_data["domains"],
                user_is_admin=api.user_cache_data["permissions"]["admin"],
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid record name")
        except DNSException as e:
            raise HTTPException(status_code=412, detail=f"Invalid type {e.type_}")
        except SubdomainError as e:
            raise HTTPException(
                status_code=403,
                detail=f"You need to own {e.required_domain} before registering {body.domain}",
            )
        except DomainExistsError:
            raise HTTPException(status_code=409, detail="Domain is already registered")

        if not is_domain_available:
            raise HTTPException(status_code=409, detail="Domain is not available")

        try:
            domain_exists_in_dns = self.dns.record_exists(body.domain, body.type)
        except DNSException:
            logger.exception("DNSException occurred while checking existing DNS records:")
            raise HTTPException(status_code=500, detail="DNS availability check failed")

        if domain_exists_in_dns:
            raise HTTPException(status_code=409, detail="Domain is already registered")

        try:
            self.dns.register_domain(
                body.domain,
                body.values[0],
                body.type,
                f"Registered through API user: {api.username}",
            )
        except DNSException:
            logger.exception("DNSException occurred during domain registration:")
            raise HTTPException(status_code=500, detail="DNS Registration failed")

        self.domains.add_domain(
            api.username,
            body.domain,
            {
                "id": "None",
                "type": body.type,
                "ip": body.values,
                "registered": round(time.time()),
            },
        )

    @Api.requires_auth
    @Api.requires_permission("modify")
    def modify(
        self,
        body: DomainType,
        api: Api = Depends(converter.create),
    ) -> None:
        if not self.dns_validation.record_name_valid(body.domain, body.type):
            raise HTTPException(
                status_code=412,
                detail=f"Invalid domain name {body.domain}",
            )

        if not self.dns_validation.record_value_valid(body.values, body.type):
            raise HTTPException(
                status_code=412,
                detail=f"Invalid value in {body.values}",
            )

        if not self.dns_validation.user_owns_domain(api.username, body.domain):
            raise HTTPException(
                status_code=403,
                detail=f"You do not own the domain {body.domain}",
            )

        domain_data = self.domains.get_domain(api.user_cache_data["domains"], body.domain)
        if domain_data is None:
            raise HTTPException(status_code=403, detail=f"You do not own the domain {body.domain}")

        try:
            self.dns.modify_domain(
                values=body.values,
                type=body.type,
                old_type=domain_data["type"],
                domain=body.domain,
                user_id=api.username,
            )

        except ValueError:  # domain id is corrupt
            logger.exception(f"Domain valueerror {body.domain} is corrupted")
        except DNSException as e:
            print(e.json)
            raise HTTPException(status_code=500)

        self.domains.add_domain(
            api.username,
            body.domain,
            {
                "id": "None",
                "ip": body.values,
                "registered": round(time.time()),
                "type": body.type,
            },
        )

    @Api.requires_auth
    @Api.requires_permission("delete")
    def delete(
        self,
        domain: str,
        type: str | None = None,
        api: Api = Depends(converter.create),
    ) -> None:
        if type is None:
            domain_data = self.domains.get_domain(api.user_cache_data["domains"], domain)
            if domain_data is None:
                raise HTTPException(
                    status_code=404,
                    detail="Domain type could not be fetched. Please specify it manually with the `type` query param",
                )
            type = domain_data["type"]

        if not self.domains.delete_domain(api.username, domain):
            raise HTTPException(
                status_code=403,
                detail="Domain does not exist, or user does not own it.",
            )
        if not self.dns.delete_domain(domain, type):
            raise HTTPException(
                status_code=403,
                detail="DNS deletion failed: maybe the domain doesnt exist? Try specifying a type manually",
            )

    @Api.requires_auth
    @Api.requires_permission("list")
    def get_domains(
        self,
        api: Api = Depends(converter.create),
    ) -> list[DomainRecord]:
        return api.user_domains

    def is_available(self, name: str) -> None:
        if not self.dns_validation.is_free(name, "A", {}, raise_exceptions=False):
            raise HTTPException(
                status_code=409,
                detail=f"Domain {name} is not available",
            )

    @Api.requires_auth
    @Api.requires_permission("userdetails")
    def get_user_profile(self, api: Api = Depends(converter.create)) -> UserPageType:
        try:
            return self.table.get_user_profile(api.user_id, self.sessions)
        except UserNotExistError:
            raise HTTPException(status_code=404, detail="Could not find user")

    @Api.requires_auth
    def get_key_intents(
        self,
        api: Api = Depends(converter.create),
    ) -> list[ApiPermission]:
        return api.permissions
