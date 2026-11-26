# ruff: noqa: ARG002

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, cast

import ipinfo
from fastapi import APIRouter, Depends, Header, Request
from fastapi.exceptions import HTTPException

from config.env import Environment
from database.exceptions import (
    ConflictingReferralCode,
    FilterMatchError,
)
from database.tables.codes import Codes, CodeStatus
from database.tables.domains import Domains
from database.tables.invitation import Invites
from database.tables.reward_codes import Rewards
from database.tables.sessions import Sessions
from database.tables.users import UserPageType, Users
from dns_.dns import DNS
from mail.email import Email
from security.api import Api, ApiKeyLimitError, ApiPermission, ApiType
from security.captcha import Captcha
from security.convert import Convert
from security.encryption import Encryption
from security.session import (
    Session,
)
from server.models.user import (
    ApiCreationBody,
    ApiDeletion,
    MFACreation,
    MfaRecovery,
    PasswordReset,
    YearWrapped,
)

if TYPE_CHECKING:
    from dns_.types import TYPES

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("eepy.page")


class User:
    def __init__(  # noqa: PLR0913
        self,
        *,
        table: Users,
        session_table: Sessions,
        invite_table: Invites,
        email: Email,
        codes: Codes,
        dns: DNS,
        rewards: Rewards,
    ) -> None:
        converter.init_vars(table, session_table)

        self.table: Users = table
        self.session_table: Sessions = session_table
        self.invites: Invites = invite_table
        self.email: Email = email
        self.codes: Codes = codes
        self.dns: DNS = dns
        self.rewards: Rewards = rewards
        self.captcha: Captcha = Captcha(Environment.turnstile_key())

        self.encryption: Encryption = Encryption(Environment.enc_key())

        self.handler: ipinfo.Handler = ipinfo.getHandler(Environment.ipinfo_key())

        self.router = APIRouter()

        self.router.add_api_route(
            "/settings",
            self.get_settings,
            methods=["GET"],
            responses={
                200: {"description": "Settings retrieved"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/redeem",
            self.redeem_code,
            methods=["POST"],
            responses={
                200: {"description": "successfully redeemed code"},
                412: {"description": "Invalid code"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "kofi"],
        )

        self.router.add_api_route(
            "/email/send",
            self.resend_verification,
            methods=["POST"],
            responses={
                200: {"description": "Email sent successfully"},
                404: {"description": "Account does not exist"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/email/verify",
            self.verify_account,
            methods=["POST"],
            responses={
                200: {"description": "Verified successfully"},
                400: {"description": "Code is invalid"},
                404: {"description": "Account does not exist"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/deletion/send",
            self.send_account_deletion,
            methods=["DELETE"],
            responses={
                200: {"description": "Deletion email sent"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/deletion/verify",
            self.verify_deletion,
            methods=["DELETE"],
            responses={
                200: {"description": "Account deleted"},
                400: {"description": "Deletion code invalid"},
                404: {"description": "Account not found"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/recovery/send",
            self.send_recovery_link,
            methods=["POST"],
            responses={200: {"description": "Email sent"}},
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/recovery/verify",
            self.reset_password,
            methods=["POST"],
            responses={
                200: {"description": "Email sent"},
                403: {"description": "Invalid code"},
                404: {"description": "User not found"},
            },
            status_code=200,
            tags=["account"],
        )

        self.router.add_api_route(
            "/gdpr",
            self.get_gdpr,
            methods=["GET"],
            responses={
                200: {"description": "GDPR data sent"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "privacy"],
        )

        self.router.add_api_route(
            "/profile/wrapped",
            self.year_wrapped,
            methods=["GET"],
            responses={
                200: {"description": "Wrapped sent"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "fun"],
        )

        self.router.add_api_route(
            "/referral",
            self.create_referral,
            methods=["POST"],
            responses={
                200: {"description": "Created referral"},
                400: {"description": "Invalid code length"},
                409: {"description": "Referral code has already been created"},
                412: {"description": "User has already created a codee"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "referral"],
        )

        self.router.add_api_route(
            "/api/create-key",
            self.create_api_token,
            methods=["POST"],
            responses={
                403: {"description": "User does not own requested domains"},
                409: {"description": "Account already has an API key"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/get-keys",
            self.get_api_keys,
            methods=["GET"],
            responses={
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/get-key",
            self.get_key,
            methods=["GET"],
            responses={
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/api/delete-key",
            self.delete_api_key,
            methods=["DELETE"],
            responses={
                404: {"description": "Key does not exist"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "api"],
        )

        self.router.add_api_route(
            "/mfa/create",
            self.create_mfa,
            methods=["POST"],
            responses={
                409: {"description": "Code already exists"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        self.router.add_api_route(
            "/mfa/verify",
            self.verify_mfa_setup,
            methods=["POST"],
            responses={
                401: {"description": "Invalid code"},
                409: {"description": "Code already exists"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        self.router.add_api_route(
            "/mfa/delete",
            self.delete_mfa,
            methods=["DELETE"],
            responses={
                401: {"description": "Invalid code"},
                460: {"description": "Invalid session"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )
        self.router.add_api_route(
            "/mfa/recovery",
            self.delete_mfa_with_username_pass,
            methods=["DELETE"],
            responses={
                401: {"description": "Invalid password"},
                404: {"description": "Account doesnt exist"},
                409: {"description": "Invalid recovery code"},
                412: {"description": "MFA not enabled"},
            },
            status_code=200,
            tags=["account", "2fa"],
        )

        logger.info("Initialized")

    def create_mfa(
        self,
        _request: Request,
        session: Session = Depends(converter.create),
    ) -> MFACreation:
        if session.user.mfa_verified:
            raise HTTPException(status_code=409, detail="MFA code already exists!")
        status = session.create_2fa()
        return MFACreation(app_link=status["url"], backup_codes=status["codes"])

    def verify_mfa_setup(
        self,
        _request: Request,
        x_mfa_code: Annotated[str, Header()],
        session: Session = Depends(converter.create),
    ) -> None:
        if session.user.mfa_verified:
            raise HTTPException(status_code=409, detail="MFA code already exists!")
        if not session.verify_2fa(x_mfa_code):
            raise HTTPException(status_code=401, detail="Code is invalid")

    def delete_mfa(
        self,
        _request: Request,
        session: Session = Depends(converter.create),
        x_mfa_code: Annotated[str | None, Header()] = None,
        x_backup_code: Annotated[str | None, Header()] = None,
    ) -> None:
        if not x_mfa_code and not x_backup_code:
            raise HTTPException(
                status_code=412,
                detail="X-MFA-Code or X-Backup-Code needs to be specified!",
            )

        try:
            session.remove_mfa(x_backup_code, x_mfa_code)
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid code")

    def delete_mfa_with_username_pass(
        self,
        _request: Request,
        body: MfaRecovery,
        x_backup_code: Annotated[str, Header()],
    ) -> None:
        user_data = self.table.find_user_by_identifier(body.username)

        if user_data is None:
            raise HTTPException(status_code=404, detail="User does not exist")

        stored_password = user_data.password
        if not stored_password or not Encryption().check_password(
            body.password,
            stored_password,
        ):
            raise HTTPException(status_code=401, detail="Invalid password")

        if not user_data.mfa_verified:
            raise HTTPException(412, detail="User does not have MFA")

        try:
            Session.remove_mfa_static(
                user_data.id,
                self.table,
                user_data,
                x_backup_code,
            )
        except ValueError:
            raise HTTPException(status_code=409)

    @Session.requires_auth
    def get_settings(
        self,
        session: Session = Depends(converter.create),
    ) -> UserPageType:
        return self.table.get_user_profile(session.user_id, self.session_table)

    @staticmethod
    def _safe_origin(request: Request) -> str:
        origin = request.headers.get("Origin", "").strip()
        safe_domains: list[str] = getattr(request.app.state, "safe_domains", [])
        if origin and origin in safe_domains:
            return origin
        return "https://www.eepy.page"

    def resend_verification(self, request: Request, user_id: str) -> None:
        from_url: str = self._safe_origin(request)

        user_data = self.table.get_user(user_id)

        if user_data is None or user_data.verified:
            # Return 200 silently so unauthenticated callers cannot enumerate accounts or verification state.
            logger.info("Skipping verification resend for unknown or already-verified account")
            return

        email: str = self.encryption.decrypt(user_data.email)

        self.email.send_verification_code(from_url, user_id, email)

    def verify_account(self, code: str) -> None:
        code_status: CodeStatus = self.codes.is_valid(code, "verification")

        account: str | None = code_status.get("account")

        if not code_status["valid"] and account is None:
            raise HTTPException(status_code=400, detail="Code is not valid")

        if not code_status["valid"] and account is not None:
            target = self.table.get_user(account)

            if target and target.verified:
                logger.info("Account is already verified")
                return
            raise HTTPException(status_code=400, detail="Code is expired or invalid")

        try:
            target_account = code_status.get("account")
            if not target_account or not self.table.set_verified(target_account, verified=True):
                msg = "User not found"
                raise FilterMatchError(msg)

            user = self.table.get_user(
                target_account,
            )
            if not user:
                msg = "User not found"
                raise FilterMatchError(msg)

            referred_by: str = user.referred_by

            if referred_by:
                logger.info("Using referral code")
                try:
                    self.table.referrals.use(user, referred_by)
                except ValueError:
                    logger.warning(f"Invalid referral code {referred_by}")

        except FilterMatchError:
            raise HTTPException(status_code=404)

        self.codes.delete_code(code, "verification")

    @Session.requires_auth
    def send_account_deletion(
        self,
        request: Request,
        x_mfa_code: Annotated[str, Header()],
        session: Session = Depends(converter.create),
    ) -> None:
        from_url: str = self._safe_origin(request)
        if session.user.mfa_verified and not session.check_code(x_mfa_code):
            raise HTTPException(status_code=412, detail="Invalid MFA code")

        email: str = self.encryption.decrypt(session.user.email)
        self.email.send_delete_code(from_url, session.user_id, email)

    @Session.requires_auth
    def year_wrapped(
        self,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> YearWrapped:
        user = self.table.get_user(session.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="Account not found")
        this_year_timestamp = datetime(
            datetime.now(UTC).year,
            1,
            1,
            tzinfo=UTC,
        ).timestamp()
        unique_ips: int = len(user.accessed_ips)

        accounts_made_after: int = self.table.count_users_created_after(user.created)

        total_users: int = self.table.count_total_users()
        domains = Domains.normalize_domains(user.domains)

        return YearWrapped(
            account_created=user.created,
            accounts_made_after=accounts_made_after,
            domains_registered=len(
                [domain for domain in domains if domain.registered > this_year_timestamp],
            ),
            total_users=total_users,
            unique_ips=unique_ips,
        )

    @Session.requires_auth
    def create_api_token(
        self,
        request: Request,
        body: ApiCreationBody,
        session: Session = Depends(converter.create),
    ) -> str:
        api_key: str
        try:
            api_key = Api.create(
                session.user_id,
                self.table,
                body.comment,
                body.permissions,
                body.domains,
            )
        except PermissionError:
            raise HTTPException(403, detail="You need to own domains specified")
        except ApiKeyLimitError:
            raise HTTPException(409, detail="Only one API key is allowed per account")

        return api_key

    @Session.requires_auth
    def get_api_keys(
        self,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> dict[str, ApiType]:
        return {
            ak.id: ApiType(
                string=ak.string,
                perms=cast("list[ApiPermission]", list(ak.perms or [])),
                domains=[
                    Domains.canonical_full_domain_name(domain) if domain != "*" else "*"
                    for domain in (ak.domains or [])
                ],
                comment=ak.comment,
            )
            for ak in (session.user.api_keys or [])
        }

    @Session.requires_auth
    def get_key(
        self,
        hash: str,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> str:
        key_entry = next((ak for ak in (session.user.api_keys or []) if ak.id == hash), None)
        if key_entry is None:
            raise HTTPException(status_code=404, detail="Key does not exist!")

        if not key_entry.string:
            raise HTTPException(status_code=412, detail="Wrong API key format!")

        return self.encryption.decrypt(key_entry.string)

    @Session.requires_auth
    def delete_api_key(
        self,
        body: ApiDeletion,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> None:
        if not any(ak.id == body.hash for ak in (session.user.api_keys or [])):
            raise HTTPException(status_code=404, detail="Key does not exist")

        self.table.delete_api_key(session.user.id, body.hash)

    @Session.requires_auth
    def get_gdpr(
        self,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> dict[Any, Any]:
        user_data = session.user
        return {
            "_id": user_data.id,
            "lang": user_data.lang,
            "country": dict(user_data.country or {}),
            "created": user_data.created,
            "credits": user_data.credits,
            "last_login": user_data.last_login,
            "permissions": user_data.permissions_dict(),
            "verified": user_data.verified,
            "domains": [d.model_dump() for d in Domains.normalize_domains(user_data.domains)],
            "feature_flags": dict(user_data.feature_flags or {}),
        }

    @Session.requires_auth
    def create_referral(
        self,
        code: str,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> None:
        if session.user.referral_code:
            raise HTTPException(
                status_code=412,
                detail="User already has referral code!",
            )

        try:
            self.table.referrals.create(session.user_id, code)
        except ConflictingReferralCode:
            raise HTTPException(status_code=409, detail="Referral code taken")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid code length")

    @Session.requires_auth
    def redeem_code(
        self,
        code: str,
        request: Request,
        session: Session = Depends(converter.create),
    ) -> None:
        if not self.rewards.use(session.user_id, code):
            raise HTTPException(status_code=412, detail="Invalid code!")

    def verify_deletion(self, code: str) -> None:
        code_status: CodeStatus = self.codes.is_valid(code, "deletion")

        if not code_status["valid"]:
            raise HTTPException(status_code=400, detail="Code is not valid")

        user_id: str = code_status.get("account", "")
        user_data = self.table.get_user(user_id)

        if user_data is None:
            raise HTTPException(status_code=404, detail="Account not found")

        domains: list[tuple[str, TYPES]] = [
            (domain.name, domain.type) for domain in Domains.normalize_domains(user_data.domains)
        ]

        success = self.dns.delete_multiple(domains)
        if not success:
            logger.error(
                "Domain mass deletion failed! Continuing with account deletion.",
            )

        # Clear legacy owner_hash sessions explicitly; Postgres ON DELETE CASCADE removes all other user-owned rows.
        Session.clear_sessions(user_id, self.session_table)
        self.table.delete_by_id(user_id)
        self.codes.delete_code(code, "deletion")

    def send_recovery_link(self, username: str) -> None:  # username being a plaintext string
        try:
            self.email.send_password_code(username)
        except Exception:
            logger.exception("Failed to send password recovery email")

    def reset_password(self, body: PasswordReset) -> None:
        code_status: CodeStatus = self.codes.is_valid(body.code, "recovery")

        if not code_status["valid"]:
            raise HTTPException(status_code=403, detail="Invalid code")

        password: str = self.encryption.create_password(body.password)
        username: str = code_status.get("account", "")

        Session.clear_sessions(username, self.session_table)

        if not self.table.set_password(username, password):
            raise HTTPException(status_code=404, detail="Invalid user")

        self.codes.delete_code(body.code, "recovery")
