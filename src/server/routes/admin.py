# ruff: noqa: ARG002

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import get_args

import jwt
import requests
from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import HTTPException

from config.env import Environment
from database.exceptions import UserNotExistError
from database.tables.sessions import Sessions
from database.tables.status import Status
from database.tables.users import Users, UserType
from dns_.dns import sanitize
from dns_.exceptions import DNSException
from dns_.types import ALLOWED_TYPES, AVAILABLE_TLDS
from mail.email import normalize_email_address
from security.admin import AccountData, DomainDeletionError
from security.admin import Admin as AdminTools
from security.admin_permissions import admin_is_enabled
from security.convert import Convert
from security.risk import FLAGGED_THRESHOLD
from security.session import Session
from server.models.admin import (
    AdminDomainEdit,
    AdminPermissionChange,
    AdminStatusMessage,
    BanUser,
    IpFind,
    ManualLoginTermination,
    RiskUpdateBody,
    UserAction,
    UserDisabledBody,
)

MAX_SAFE_32BIT_INT = 2**31 - 1

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("eepy.page")


class Admin:
    def __init__(
        self,
        user_table: Users,
        session_table: Sessions,
        status_table: Status,
        admin: AdminTools,
    ) -> None:
        converter.init_vars(user_table, session_table)

        self.router = APIRouter(prefix="/admin")
        self.admin_tools = admin
        self.sessions = session_table
        self.users = user_table
        self.status_table = status_table

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
            "/domain/detail",
            self.domain_detail,
            methods=["GET"],
            responses={
                200: {"description": "Domain details returned"},
                404: {"description": "User or domain not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/domain/edit",
            self.edit_domain,
            methods=["PATCH"],
            responses={
                200: {"description": "Domain updated"},
                404: {"description": "User or domain not found"},
                412: {"description": "Invalid domain name or value"},
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
                400: {"description": "Invalid regex pattern"},
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
            "/user/manual-login/terminate",
            self.terminate_manual_login,
            methods=["POST"],
            responses={
                200: {"description": "Manual login session terminated"},
                404: {"description": "Manual login session not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/dns/desync",
            self.find_desync,
            methods=["GET"],
            responses={200: {"description": "PostgreSQL/PowerDNS synchronization report"}},
            tags=["admin"],
        )

        self.router.add_api_route(
            "/status",
            self.set_status,
            methods=["POST"],
            responses={
                200: {"description": "Status updated"},
                412: {"description": "Invalid status message"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/status/clear",
            self.clear_status,
            methods=["POST"],
            responses={
                200: {"description": "Status cleared"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/risk/update",
            self.update_user_risk,
            methods=["POST"],
            responses={
                200: {"description": "User risk updated"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/user/disabled",
            self.toggle_user_disabled,
            methods=["POST"],
            responses={
                200: {"description": "User disabled state toggled"},
                404: {"description": "User not found"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        self.router.add_api_route(
            "/users/flagged",
            self.get_flagged_users,
            methods=["GET"],
            responses={
                200: {"description": "List of flagged and disabled users"},
                460: {"description": "Invalid session"},
                461: {"description": "Invalid permissions"},
            },
            tags=["admin"],
        )

        logger.info("Initialized")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def delete_user(self, body: BanUser, session: Session = Depends(converter.create)) -> None:
        user_data: UserType | None = self.users.get_user(body.user_id)
        if user_data is None:
            raise HTTPException(status_code=404, detail="User not found")

        try:
            status = self.admin_tools.ban_user(body.reasons, user_data, send_email=body.send_email)
        except DomainDeletionError:
            raise HTTPException(status_code=503, detail="Failed to delete domains")

        if not status:
            raise HTTPException(500, detail="Failed to delete user")

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def reinstate_user(
        self,
        user_id: str,
        send_email: bool = False,
        session: Session = Depends(converter.create),
    ) -> None:
        try:
            self.admin_tools.reinstate_user(user_id, send_email=send_email)
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
        send_email: bool = False,
        session: Session = Depends(converter.create),
    ) -> None:
        target_user = self.admin_tools.get_user_details_by_id(userid)
        if not target_user:
            raise HTTPException(status_code=404, detail="Couldnt find a user")

        email: str = target_user["email"]
        domain_data = self.admin_tools.domains.get_domain(target_user["domains"], domain)
        if domain_data is None:
            raise HTTPException(status_code=404, detail="Domain not found")

        normalized_domain = self.admin_tools.domains.canonical_domain_name(domain)
        dns_success = self.admin_tools.dns.delete_domain(
            normalized_domain,
            domain_data["type"],
        )

        if dns_success:
            if self.admin_tools.domains.delete_domain(userid, domain):
                if send_email:
                    self.admin_tools.email.send_domain_termination_email(
                        email,
                        normalized_domain,
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
    def domain_detail(
        self,
        user_id: str,
        domain: str,
        type: str | None = None,
        session: Session = Depends(converter.create),
    ) -> dict[str, object]:
        user = self.users.get_user(user_id, find_banned=True)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        domain_data = self.admin_tools.domains.get_domain(user.get("domains"), domain, type)
        if domain_data is None:
            raise HTTPException(status_code=404, detail="Domain not found")

        return {"user_id": user_id, "domain": domain_data}

    @Session.requires_auth
    @Session.requires_permission(permission="dns")
    def edit_domain(  # noqa: C901, PLR0912
        self,
        body: AdminDomainEdit,
        session: Session = Depends(converter.create),
    ) -> dict[str, object]:
        user = self.users.get_user(body.user_id, find_banned=True)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        values = [value.strip() for value in body.values]
        if not values or any(value == "" for value in values):
            raise HTTPException(status_code=412, detail="At least one non-empty value is required")
        if not self.admin_tools.dns_validation.record_name_valid(body.domain, body.type):
            raise HTTPException(status_code=412, detail=f"Invalid domain name {body.domain}")
        if not self.admin_tools.dns_validation.record_value_valid(values, body.type):
            raise HTTPException(status_code=412, detail=f"Invalid value in {values}")

        domain_data = self.admin_tools.domains.get_domain(user.get("domains"), body.domain, body.old_type or body.type)
        if domain_data is None:
            raise HTTPException(status_code=404, detail="Domain not found")
        if (
            body.type != domain_data["type"]
            and self.admin_tools.domains.get_domain(user.get("domains"), body.domain, body.type) is not None
        ):
            raise HTTPException(status_code=409, detail="Domain is already registered with that type")

        if body.mode in {"both", "pdns"}:
            try:
                if not self.admin_tools.dns.modify_domain(
                    values=values,
                    type=body.type,
                    old_type=domain_data["type"],
                    domain=body.domain,
                    user_id=body.user_id,
                ):
                    msg = "Not successful"
                    raise DNSException(msg, {"success": False})
            except DNSException as error:
                logger.exception("Admin DNS domain edit failed")
                raise HTTPException(status_code=500, detail="PowerDNS domain update failed") from error

        if body.mode in {"both", "postgres", "db"}:
            try:
                self.admin_tools.domains.modify_domain(
                    body.user_id,
                    body.domain,
                    value=values,
                    type=body.type,
                    old_type=domain_data["type"],
                )
            except ValueError as error:
                logger.exception("Admin database domain edit failed")
                if body.mode == "both":
                    try:
                        raw: list[str] | str = domain_data["ip"]
                        self.admin_tools.dns.modify_domain(
                            values=raw if isinstance(raw, list) else [raw],
                            type=domain_data["type"],
                            old_type=body.type,
                            domain=body.domain,
                            user_id=body.user_id,
                        )
                    except DNSException:
                        logger.exception("Admin domain edit rollback failed")
                raise HTTPException(status_code=500, detail="PostgreSQL domain update failed") from error

        return {"user_id": body.user_id, "domain": body.domain, "type": body.type, "mode": body.mode}

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
    @Session.requires_permission(permission="account")
    def set_status(
        self,
        body: AdminStatusMessage,
        session: Session = Depends(converter.create),
    ) -> None:
        self.status_table.set(body.message)

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def clear_status(
        self,
        session: Session = Depends(converter.create),
    ) -> None:
        self.status_table.clear()

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def find_user_by_email(
        self,
        email: str,
        session: Session = Depends(converter.create),
    ) -> AccountData | list[AccountData]:
        clean_email = email.strip()
        normalized_email = normalize_email_address(clean_email)

        email_hashes = {self.users.encryption.hash_email(clean_email)}
        normalized_hash = self.users.encryption.hash_email(normalized_email)

        matched_ids = self.users.find_users_by_email_hashes(email_hashes, normalized_hash, limit=50)

        if not matched_ids:
            raise HTTPException(status_code=404, detail="User not found (find_item)")

        profiles: list[AccountData] = []
        for matched_id in matched_ids:
            profile = self.admin_tools.get_user_details_by_id(matched_id)
            if profile:
                profiles.append(profile)

        if not profiles:
            raise HTTPException(status_code=404, detail="User not found (get profile)")

        return profiles[0] if len(profiles) == 1 else profiles

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
        regex: bool = False,
        session: Session = Depends(converter.create),
    ) -> AccountData | list[AccountData]:
        try:
            user_data: AccountData | list[AccountData] | None = self.admin_tools.find_by_username(
                username,
                regex=regex,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

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
    @Session.requires_permission(permission="manage_permissions")
    def change_permission(
        self,
        body: AdminPermissionChange = Depends(),
        session: Session = Depends(converter.create),
    ) -> None:
        try:
            if not self.admin_tools.change_permission(
                body.id,
                body.permission,
                body.value,
                send_email=body.send_email,
            ):
                raise HTTPException(status_code=404, detail="User not found")
        except ValueError as error:
            raise HTTPException(status_code=412, detail=str(error)) from error

    @Session.requires_auth
    @Session.requires_permission(permission="manage_permissions")
    def full_admin(
        self,
        body: UserAction,
        session: Session = Depends(converter.create),
    ) -> None:
        user = self.users.get_user(body.user_id, find_banned=True)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        self.users.grant_full_admin(body.user_id, MAX_SAFE_32BIT_INT)

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def manual_login(
        self,
        body: UserAction,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> dict[str, str]:
        user = self.users.get_user(body.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        original_metadata = {field: user.get(field) for field in ("accessed_from", "last_login") if field in user}

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

        refresh_token = status["refresh_token"] or ""
        refresh_id = jwt.decode(
            refresh_token,
            options={"verify_signature": False, "verify_exp": False},
        )["jti"]
        self.sessions.set_manual_login(refresh_id, body.user_id, original_metadata)

        return {
            "access_token": status["access_token"] or "",
            "refresh_token": refresh_token,
        }  # pyright: ignore[reportReturnType]

    @Session.requires_auth
    @Session.requires_permission(permission="account")
    def terminate_manual_login(
        self,
        body: ManualLoginTermination,
        session: Session = Depends(converter.create),
    ) -> None:
        try:
            refresh_id = jwt.decode(
                body.refresh_token,
                options={"verify_signature": False, "verify_exp": False},
            )["jti"]
        except (jwt.InvalidTokenError, KeyError, TypeError):
            raise HTTPException(status_code=404, detail="Manual login session not found")

        session_data = self.sessions.get_session(refresh_id)
        manual_login = session_data.get("manual_login") if session_data else None
        if not isinstance(manual_login, Mapping) or manual_login.get("user_id") != body.user_id:
            raise HTTPException(status_code=404, detail="Manual login session not found")

        metadata = manual_login.get("metadata", {})
        if isinstance(metadata, Mapping):
            self.users.restore_login_metadata(body.user_id, metadata)

        if not self.sessions.delete_session_pair(refresh_id):
            raise HTTPException(status_code=404, detail="Manual login session not found")

    @Session.requires_auth
    @Session.requires_permission(permission="dns")
    def find_desync(  # noqa: C901, PLR0912, PLR0915
        self,
        session: Session = Depends(converter.create),
    ) -> dict[str, object]:
        powerdns_url = Environment.pdns_domain().rstrip("/")
        api_key = Environment.pdns_api_key()
        if not powerdns_url or not api_key:
            raise HTTPException(status_code=503, detail="PowerDNS configuration is unavailable")

        postgres_records: dict[tuple[str, str], list[tuple[str, ...]]] = defaultdict(list)
        owners: dict[tuple[str, str], set[str]] = defaultdict(set)
        for user_id, domain in self.admin_tools.domains.get_all_domain_records():
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
            normalized = tuple(
                sorted(sanitize(value, record_type) for value in values if isinstance(value, str)),
            )
            key = (self.admin_tools.domains.canonical_full_domain_name(name), record_type)
            postgres_records[key].append(normalized)
            owners[key].add(str(user_id))

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
                    powerdns_records[key].append(
                        tuple(sorted(sanitize(value, record_type) for value in values)),
                    )
        except requests.RequestException as error:
            raise HTTPException(status_code=503, detail="PowerDNS request failed") from error

        postgres_keys, powerdns_keys = set(postgres_records), set(powerdns_records)

        def describe(key: tuple[str, str]) -> str:
            return f"{key[0]} [{key[1]}]"

        duplicate_postgres = [
            f"{describe(key)} appears {len(values)} times for users {', '.join(sorted(owners[key]))}"
            for key, values in postgres_records.items()
            if len(values) > 1
        ]
        missing_from_powerdns = [describe(key) for key in sorted(postgres_keys - powerdns_keys)]
        missing_from_postgres = [describe(key) for key in sorted(powerdns_keys - postgres_keys)]
        mismatches = [
            f"{describe(key)}: PostgreSQL={sorted(set(postgres_records[key]))} "
            f"PowerDNS={sorted(set(powerdns_records[key]))}"
            for key in sorted(postgres_keys & powerdns_keys)
            if set(postgres_records[key]) != set(powerdns_records[key])
        ]

        issues = {
            "duplicate_postgres": duplicate_postgres,
            "missing_from_powerdns": missing_from_powerdns,
            "missing_from_postgres": missing_from_postgres,
            "value_mismatches": mismatches,
        }
        return {"postgres_keys": len(postgres_keys), "powerdns_keys": len(powerdns_keys), "issues": issues}

    @Session.requires_auth
    @Session.requires_permission(permission="manage_permissions")
    def add_tld(
        self,
        id: str,
        tld: str,
        send_email: bool = False,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.add_domain(id, tld, send_email=send_email)  # pyright: ignore[reportArgumentType]

    @Session.requires_auth
    @Session.requires_permission(permission="manage_permissions")
    def remove_tld(
        self,
        id: str,
        tld: str,
        send_email: bool = False,
        session: Session = Depends(converter.create),
    ) -> None:
        if tld not in get_args(AVAILABLE_TLDS):
            raise HTTPException(status_code=412, detail=f"Invalid TLD {tld}")

        self.admin_tools.remove_domain(id, tld, send_email=send_email)  # pyright: ignore[reportArgumentType]

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
        if not admin_is_enabled(session.user_cache_data):
            raise HTTPException(status_code=403, detail="Invalid permission")

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def get_flagged_users(
        self,
        session: Session = Depends(converter.create),
    ) -> list[AccountData]:
        results: list[AccountData] = []
        for migrated_user in self.users.find_flagged_users(FLAGGED_THRESHOLD):
            try:
                user_details = self.admin_tools.get_user_details_by_id(
                    migrated_user["_id"],
                    migrated_user,
                )
                if user_details:
                    results.append(user_details)
            except Exception:
                logger.exception(f"Failed to load flagged user {migrated_user.get('_id')}")
        results.sort(
            key=lambda item: (
                -int(item.get("risk", {}).get("score", 0)),
                (item.get("username") or "").lower(),
            ),
        )
        return results

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def update_user_risk(
        self,
        body: RiskUpdateBody,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user = self.users.get_user(body.user_id, find_banned=True)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        self.users.update_user_risk_fields(
            body.user_id,
            score=body.score,
            locked=body.locked,
            clear_flags=body.clear_flags,
        )
        updated_profile = self.admin_tools.get_user_details_by_id(body.user_id)
        if not updated_profile:
            raise HTTPException(status_code=404, detail="User not found after update")
        return updated_profile

    @Session.requires_auth
    @Session.requires_permission(permission="userdetails")
    def toggle_user_disabled(
        self,
        body: UserDisabledBody,
        session: Session = Depends(converter.create),
    ) -> AccountData:
        user = self.users.get_user(body.user_id, find_banned=True)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        self.users.set_user_disabled(
            body.user_id,
            disabled=body.disabled,
            reason=body.reason,
        )

        if body.send_email and user.get("email"):
            if body.disabled:
                action_text = "Your account has been temporarily disabled. If you believe this was done in error, please contact support@eepy.page."  # noqa: E501
            else:
                action_text = "Your account has been re-enabled. You may now log in to your account."

            try:
                decrypted_email = self.users.encryption.decrypt(user["email"])
                self.admin_tools.send_nonblocking_action_email(decrypted_email, action_text)
            except Exception:
                logger.exception(f"Failed to send action email for user {body.user_id}")

        updated_profile = self.admin_tools.get_user_details_by_id(body.user_id)
        if not updated_profile:
            raise HTTPException(status_code=404, detail="User not found after update")
        return updated_profile
