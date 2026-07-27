# ruff: noqa: ARG002

import logging
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import get_args

import requests
from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import HTTPException

from database.exceptions import UserNotExistError
from database.tables.sessions import Sessions
from database.tables.users import Users, UserType
from dns_.exceptions import DNSException
from dns_.types import ALLOWED_TYPES, AVAILABLE_TLDS
from security.admin import AccountData, DomainDeletionError
from security.admin import Admin as AdminTools
from security.admin_permissions import admin_is_enabled
from security.convert import Convert
from security.encryption import Encryption
from security.session import Session
from server.routes.models.admin import BanUser, IpFind, UserAction

MAX_SAFE_32BIT_INT = 2**31 - 1

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("eepy.page")


class Admin:
    def __init__(
        self,
        user_table: Users,
        session_table: Sessions,
        admin: AdminTools,
    ) -> None:
        converter.init_vars(user_table, session_table)

        self.router = APIRouter(prefix="/admin")
        self.admin_tools = admin
        self.sessions = session_table
        self.users = user_table

        self.router.add_api_route(
            "/domain/delete",
            self.delete_domain,
            methods=["DELETE"],
            responses={
                200: {"description": "Domain deleted"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/reinstate",
            self.reinstate_user,
            methods=["POST"],
            responses={
                200: {"description": "User reinstated"},
                404: {"description": "User not found"},
                412: {"description": "User already unbanned"},
                503: {"description": "Failed to recover DNS records"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/verify",
            self.verify,
            methods=["POST"],
            responses={
                200: {"description": "User verified"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/tld/add",
            self.add_tld,
            methods=["POST"],
            responses={
                200: {"description": "TLD added"},
                412: {"description": "Invalid TLD"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/tld/remove",
            self.remove_tld,
            methods=["POST"],
            responses={
                200: {"description": "TLD added"},
                412: {"description": "Invalid TLD"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/can-access",
            self.can_access,
            methods=["GET"],
            responses={
                200: {"description": "User can access the admin panel"},
                403: {"description": "User cant access the admin panel"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/delete",
            self.delete_user,
            methods=["DELETE"],
            responses={
                200: {"description": "User deleted"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/domain",
            self.find_user_by_domain,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/delete/record",
            self.delete_dns_record,
            methods=["DELETE"],
            responses={
                200: {"description": "User found"},
                503: {"description": "Failed to delete record"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/id",
            self.find_user_by_id,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/username",
            self.find_user_by_username,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/email",
            self.find_user_by_email,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/ips",
            self.find_user_by_ips,
            methods=["POST"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/get/referral",
            self.find_user_by_referral,
            methods=["GET"],
            responses={
                200: {"description": "User found"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/permission",
            self.change_permission,
            methods=["PATCH"],
            responses={
                200: {"description": "Permission changed"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/full-admin",
            self.full_admin,
            methods=["POST"],
            responses={200: {"description": "Full admin access granted"}},
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/manual-login",
            self.manual_login,
            methods=["POST"],
            responses={200: {"description": "Manual login session created"}},
            tags=["admin"],
        )

        self.router.add_api_route(
            "/dns/desync",
            self.find_desync,
            methods=["GET"],
            responses={200: {"description": "MongoDB/PowerDNS synchronization report"}},
            tags=["admin"],
        )

        logger.info("Initialized")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def delete_user(self, body: BanUser, session: Session = Depends(converter.create)) -> None:
        user_data: UserType | None = self.users.find_user({"_id": body.user_id})
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found")

        try:
            status = self.admin_tools.ban_user(body.reasons, user_data)
        except DomainDeletionError:
            raise HTTPException(status_code=503, detail="Failed to delete domains")

        if not status:
            raise HTTPException(500, detail="Failed to delete user")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def reinstate_user(
        self,
        user_id: str,
        session: Session = Depends(converter.create),
    ) -> None:
        try:
            self.admin_tools.reinstate_user(user_id)
        except UserNotExistError:
            raise HTTPException(status_code=404, detail="User not found")
        except ValueError:
            raise HTTPException(status_code=412, detail="User not banneds")
        except DNSException:
            raise HTTPException(status_code=503, detail="Failed to recover DNS records")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def delete_domain(
        self,
        domain: str,
        userid: str,
        reason: str,
        session: Session = Depends(converter.create),
    ) -> None:
        target_user = self.admin_tools.get_user_details_by_id(userid)
        if not target_user:
            raise HTTPException(status_code=404, detail="Couldnt find a user")

        email: str = target_user["email"]
        domain_data = self.admin_tools.domains.get_domain(target_user["domains"], domain)
        if domain_data is None:
            raise HTTPException(status_code=404, detail="Domain not found")

        dns_success = self.admin_tools.dns.delete_domain(
            self.admin_tools.domains.display_domain_name(domain),
            domain_data["type"],
        )

        if dns_success:
            if self.admin_tools.domains.delete_domain(userid, domain):
                self.admin_tools.email.send_domain_termination_email(
                    email,
                    self.admin_tools.domains.display_domain_name(domain),
                    reason,
                )
                logger.info(f"Deleted domain {domain}")
            else:
                logger.warning("Failed to delete domain (DB)")
        else:
            logger.warning("Failed to delete domain (DNS)")
            raise HTTPException(status_code=500, detail="Failed to delete domain")

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_domain(
        self,
        domain: str,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user_profile: AccountData | None = self.admin_tools.find_user_by_domain(domain)
        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_referral(
        self,
        referral: str,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user_profile: AccountData | None = self.admin_tools.find_by_referral(referral)
        if user_profile is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_email(
        self,
        email: str,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user_data = self.users.find_user(
            {"email-hash": Encryption.sha256(email + "supahcool")},
            find_banned=True,
        )
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found (find_item)")

        user_profile: AccountData | None = self.admin_tools.get_user_details_by_id(
            user_data["_id"],
        )

        if not user_profile:
            raise HTTPException(status_code=404, detail="User not found (get profile)")

        return user_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_ips(
        self,
        body: IpFind,
        session: Session = Depends(converter.create),
    ) -> list[AccountData]:
        user_profiles: list[AccountData] | None = self.admin_tools.find_by_ips(body.ips)
        if user_profiles is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user_profiles

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_id(
        self,
        id: str,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user_data: AccountData | None = self.admin_tools.get_user_details_by_id(id)

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        return user_data

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_username(
        self,
        username: str,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user_data: AccountData | None = self.admin_tools.find_by_username(username)

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        return user_data

    @Session.requires_auth
    @Session.requires_permission(permission="dns")
    def delete_dns_record(
        self,
        record: str,
        type: str,
        session: Session = Depends(converter.create),
    ) -> None:
        if not self.admin_tools.dns.delete_domain(record, type):
            raise HTTPException(status_code=503, detail="Failed to delete record")

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def change_permission(
        self,
        id: str,
        permission: str,
        value: bool | int | str,
        session: Session = Depends(converter.create),
    ) -> None:
        if not self.admin_tools.change_permission(id, permission, value):
            raise HTTPException(status_code=404, detail="User not found")

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def full_admin(
        self,
        body: UserAction,
        session: Session = Depends(converter.create),
    ) -> None:
        user = self.users.find_user({"_id": body.user_id}, find_banned=True)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        self.users.table.update_one(
            {"_id": body.user_id},
            {
                "$set": {
                    "permissions.admin": {
                        "enabled": True,
                        "permissions": {
                            "account": True,
                            "dns": True,
                            "manage-permissions": True,
                            "reports": True,
                            "userdetails": True,
                            "wildcards": True,
                        },
                    },
                    "permissions.limits": {
                        "max-domains": MAX_SAFE_32BIT_INT,
                        "max-subdomains": MAX_SAFE_32BIT_INT,
                    },
                    "permissions.features.invite": True,
                },
            },
        )

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def manual_login(
        self,
        body: UserAction,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> dict[str, str]:
        user = self.users.find_user({"_id": body.user_id})
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        status = Session.create(
            username=body.user_id,
            real_username=None,
            mfa_code=None,
            ip=request.client.host if request.client else "127.0.0.1",
            user_agent=request.headers.get("user-agent", "eepy.page admin panel"),
            users=self.users,
            session_table=self.sessions,
            skip_mfa=True,
        )
        if not status.get("success") or not status.get("access_token") or not status.get("refresh_token"):
            raise HTTPException(status_code=500, detail="Failed to create manual login session")

        return {
            "access_token": status["access_token"],
            "refresh_token": status["refresh_token"],
        }  # pyright: ignore[reportReturnType]

    @Session.requires_auth
    @Session.requires_permission(permission="dns")
    def find_desync(  # noqa: C901, PLR0912, PLR0915
        self,
        session: Session = Depends(converter.create),
    ) -> dict[str, object]:
        powerdns_url = os.getenv("PDNS_DOMAIN", "").rstrip("/")
        api_key = os.getenv("PDNS_API_KEY", "")
        if not powerdns_url or not api_key:
            raise HTTPException(status_code=503, detail="PowerDNS configuration is unavailable")

        mongo_records: dict[tuple[str, str], list[tuple[str, ...]]] = defaultdict(list)
        owners: dict[tuple[str, str], set[str]] = defaultdict(set)
        for user in self.users.table.find({}, {"domains": 1}):
            user_id = str(user.get("_id", "<unknown>"))
            domains = user.get("domains", [])
            if isinstance(domains, dict):
                domains = [{"name": name, **data} for name, data in domains.items() if isinstance(data, Mapping)]
            if not isinstance(domains, Iterable) or isinstance(domains, (str, bytes)):
                continue
            for domain in domains:
                if not isinstance(domain, Mapping):
                    continue
                name = domain.get("name")
                record_type = domain.get("type")
                if not isinstance(name, str) or not isinstance(record_type, str):
                    continue
                record_type = record_type.upper()
                if record_type not in ALLOWED_TYPES:
                    continue
                raw_values = domain.get("ip", [])
                values = [raw_values] if isinstance(raw_values, str) else raw_values
                if not isinstance(values, Iterable) or isinstance(values, (bytes, Mapping)):
                    continue
                normalized = tuple(sorted(value for value in values if isinstance(value, str)))
                key = (self.admin_tools.domains.canonical_full_domain_name(name), record_type)
                mongo_records[key].append(normalized)
                owners[key].add(user_id)

        powerdns_records: dict[tuple[str, str], list[tuple[str, ...]]] = defaultdict(list)
        server_url = f"{powerdns_url}/api/v1/servers/localhost"
        try:
            zones = requests.get(f"{server_url}/zones", headers={"X-API-Key": api_key}, timeout=10)
            zones.raise_for_status()
            for zone in zones.json():
                zone_name = zone.get("name")
                if not isinstance(zone_name, str):
                    continue
                zone_response = requests.get(
                    f"{server_url}/zones/{zone_name}",
                    headers={"X-API-Key": api_key},
                    timeout=10,
                )
                zone_response.raise_for_status()
                for rrset in zone_response.json().get("rrsets", []):
                    name = rrset.get("name")
                    record_type = rrset.get("type")
                    if not isinstance(name, str) or not isinstance(record_type, str):
                        continue
                    record_type = record_type.upper()
                    if record_type not in ALLOWED_TYPES:
                        continue
                    values: list[str] = []
                    for record in rrset.get("records", []):
                        if isinstance(record, Mapping) and isinstance(record.get("content"), str):
                            values.append(record["content"])
                    key = (name.rstrip(".").lower(), record_type)
                    powerdns_records[key].append(tuple(sorted(values)))
        except requests.RequestException as error:
            raise HTTPException(status_code=503, detail="PowerDNS request failed") from error

        mongo_keys, powerdns_keys = set(mongo_records), set(powerdns_records)

        def describe(key: tuple[str, str]) -> str:
            return f"{key[0]} [{key[1]}]"

        duplicate_mongo = [
            f"{describe(key)} appears {len(values)} times for users {', '.join(sorted(owners[key]))}"
            for key, values in mongo_records.items()
            if len(values) > 1
        ]
        missing_from_powerdns = [describe(key) for key in sorted(mongo_keys - powerdns_keys)]
        missing_from_mongo = [describe(key) for key in sorted(powerdns_keys - mongo_keys)]
        mismatches = [
            f"{describe(key)}: Mongo={sorted(set(mongo_records[key]))} PowerDNS={sorted(set(powerdns_records[key]))}"
            for key in sorted(mongo_keys & powerdns_keys)
            if set(mongo_records[key]) != set(powerdns_records[key])
        ]

        issues = {
            "duplicate_mongo": duplicate_mongo,
            "missing_from_powerdns": missing_from_powerdns,
            "missing_from_mongo": missing_from_mongo,
            "value_mismatches": mismatches,
        }
        return {"mongo_keys": len(mongo_keys), "powerdns_keys": len(powerdns_keys), "issues": issues}

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def add_tld(
        self,
        id: str,
        tld: str,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.add_domain(id, tld)  # pyright: ignore[reportArgumentType]

    @Session.requires_auth
    @Session.requires_permission(permission="manage-permissions")
    def remove_tld(
        self,
        id: str,
        tld: str,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.remove_domain(id, tld)  # pyright: ignore[reportArgumentType]

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def verify(
        self,
        id: str,
        session: Session = Depends(converter.create),
    ) -> None:
        self.admin_tools.verify(id)

    @Session.requires_auth
    def can_access(self, session: Session = Depends(converter.create)) -> None:
        if not admin_is_enabled(session.user_cache_data):  # pyright: ignore[reportArgumentType]
            raise HTTPException(status_code=403, detail="Invalid permission")
