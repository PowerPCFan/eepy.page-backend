import json
import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

import requests
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm.attributes import flag_modified

from config.env import Environment
from database.exceptions import (
    EmailException,
    InviteException,
    ReferralError,
    UsernameException,
    UserNotExistError,
)
from database.models import (
    AltLink,
    ApiKey,
    Domain,
    Invite,
    SessionModel,
    User,
    UserDevice,
    UserIP,
    UserMFA,
    UserOwnedTLD,
    UserPermissions,
    UserRiskProfile,
)
from database.session import rowcount
from database.table import Table
from database.tables.domains import Domains
from database.tables.ip_activity import IPActivity, RecentLogouts
from database.tables.referrals import Referrals
from mail.email import Email, normalize_email_address
from security.encryption import Encryption
from security.risk import RiskManager, UserRisk, normalize_device_id
from server.models.user import CountryInfo, InviteType, UserPageType

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from database.tables.sessions import Sessions as SessionTable

logger: logging.Logger = logging.getLogger("eepy.page")

USER_MIGRATION_VERSION = 2

type UserMigrationStep = Callable[[User, "Users"], None]

USER_MIGRATIONS: dict[int, UserMigrationStep] = {}


def register_user_migration(version: int) -> Callable[[UserMigrationStep], UserMigrationStep]:
    def decorator(func: UserMigrationStep) -> UserMigrationStep:
        USER_MIGRATIONS[version] = func
        return func

    return decorator


@register_user_migration(2)
def _migrate_normalize_country_fields(user: User, _users: "Users") -> None:
    normalized = CountryInfo.from_raw(user.country).model_dump()
    if user.country != normalized:
        user.country = normalized
        flag_modified(user, "country")


__all__ = [
    "USER_MIGRATIONS",
    "USER_MIGRATION_VERSION",
    "CountryInfo",
    "InviteType",
    "UserPageType",
    "Users",
    "register_user_migration",
]


class Users(Table[User]):
    def __init__(self, db_engine: "Engine | None" = None) -> None:
        super().__init__(db_engine, User)
        self.encryption: Encryption = Encryption(Environment.enc_key() or "none")
        self.referrals: Referrals = Referrals(self.engine, self)
        self.ip_activity: IPActivity = IPActivity(self.engine)
        self.recent_logouts: RecentLogouts = RecentLogouts(self.engine)
        self.risk_manager: RiskManager = RiskManager(
            ip_activity=self.ip_activity,
            recent_logouts=self.recent_logouts,
        )

    def get_user(self, user_id: str, find_banned: bool = False) -> User | None:
        with self.session() as session:
            row = session.get(User, user_id)
        if row is None:
            return None
        user = self.perform_migrations(row)
        if user.banned and not find_banned:
            return None
        return user

    def find_user_by_identifier(self, identifier: str, find_banned: bool = False) -> User | None:
        """Find a user by exact username, case-insensitive username, or email address."""
        clean_id = identifier.strip()
        if not clean_id:
            return None

        exact_id = Encryption.sha256(clean_id)
        lower_username_hash = Encryption.sha256(clean_id.lower())

        with self.session() as session:
            row = session.get(User, exact_id)
            if row is not None and row.banned and not find_banned:
                row = None

            if row is None:
                conditions = [User.username == lower_username_hash]
                if "@" in clean_id:
                    conditions.append(User.email_hash == self.encryption.hash_email(clean_id))
                stmt = select(User).where(or_(*conditions))
                if not find_banned:
                    stmt = stmt.where(User.banned.is_(False))
                row = session.scalars(stmt).first()

            if row is None:
                return None

        user = self.perform_migrations(row)
        if user.banned and not find_banned:
            return None
        return user

    def find_user_by_username_hash(self, username: str, find_banned: bool = False) -> User | None:
        exact_hash = Encryption.sha256(username)
        lower_hash = Encryption.sha256(username.lower())
        with self.session() as session:
            stmt = select(User).where(
                or_(
                    User.id == exact_hash,
                    User.username == lower_hash,
                ),
            )
            row = session.scalars(stmt).first()
            if row is None:
                return None
        user = self.perform_migrations(row)
        if user.banned and not find_banned:
            return None
        return user

    def find_users_by_ips(self, ips: list[str]) -> list[User]:
        clean_ips = [ip.strip() for ip in ips if ip and ip.strip()]
        if not clean_ips:
            return []
        with self.session() as session:
            stmt = select(User).join(UserIP, UserIP.user_id == User.id).where(UserIP.ip.in_(clean_ips)).distinct()
            return list(session.scalars(stmt).all())

    def find_shared_device_user(self, user_id: str, device_id: str) -> str | None:
        clean_dev = normalize_device_id(device_id)
        if not clean_dev:
            return None
        with self.session() as session:
            stmt = (
                select(UserDevice.user_id)
                .outerjoin(UserPermissions, UserPermissions.user_id == UserDevice.user_id)
                .where(
                    UserDevice.device_id == clean_dev,
                    UserDevice.user_id != user_id,
                    or_(
                        UserPermissions.admin_enabled.is_(None),
                        UserPermissions.admin_enabled.is_(False),
                    ),
                )
            )
            return session.scalars(stmt).first()

    def is_non_admin_user(self, user_id: str) -> bool:
        with self.session() as session:
            stmt = (
                select(User.id)
                .outerjoin(UserPermissions, UserPermissions.user_id == User.id)
                .where(
                    User.id == user_id,
                    or_(
                        UserPermissions.admin_enabled.is_(None),
                        UserPermissions.admin_enabled.is_(False),
                    ),
                )
            )
            return session.scalars(stmt).first() is not None

    def record_device(self, user_id: str, device_id: str, timestamp: int | None = None) -> None:
        clean_dev = normalize_device_id(device_id)
        if not clean_dev:
            return
        now_ts = round(time.time()) if timestamp is None else int(timestamp)
        with self.session() as session:
            if session.get(User, user_id) is None:
                return
            existing = session.get(UserDevice, (user_id, clean_dev))
            if existing is not None:
                existing.last_seen = now_ts
                session.add(existing)
            else:
                session.add(
                    UserDevice(
                        user_id=user_id,
                        device_id=clean_dev,
                        first_seen=now_ts,
                        last_seen=now_ts,
                    ),
                )

    def get_alt_links(self, user_id: str) -> list[dict[str, Any]]:
        """Return all alt-detection links involving a user from either direction."""
        with self.session() as session:
            stmt = select(AltLink).where(
                or_(
                    AltLink.user_id == user_id,
                    AltLink.related_user_id == user_id,
                ),
            )
            rows = session.scalars(stmt).all()
            return [
                {
                    "id": row.id,
                    "user_id": row.user_id,
                    "related_user_id": row.related_user_id,
                    "signal_type": row.signal_type,
                    "score": row.score,
                    "reason": row.reason,
                    "detected_at": row.detected_at,
                    "expires_at": row.expires_at,
                    "permanent": row.permanent,
                }
                for row in rows
            ]

    def create_api_key(  # noqa: PLR0913
        self,
        user_id: str,
        *,
        key_hash: str,
        encrypted_key: str,
        perms: list[str],
        domains: list[str],
        comment: str,
    ) -> None:
        with self.session() as session:
            if session.get(User, user_id) is None:
                msg = "User not found"
                raise UserNotExistError(msg)
            session.merge(
                ApiKey(
                    id=key_hash,
                    user_id=user_id,
                    string=encrypted_key,
                    perms=list(perms),
                    domains=list(domains),
                    comment=comment,
                ),
            )

    def set_verified(self, user_id: str, *, verified: bool = True) -> bool:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return False
            user.verified = verified
            session.add(user)
            return True

    def set_password(self, user_id: str, password_hash: str) -> bool:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return False
            user.password = password_hash
            session.add(user)
            return True

    def set_mfa(
        self,
        user_id: str,
        secret_key: str,
        recovery_codes: list[str],
        *,
        verified: bool = False,
    ) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                msg = "User does not exist!"
                raise UserNotExistError(msg)
            mfa = user.mfa or UserMFA(user_id=user_id)
            mfa.secret_key = secret_key
            mfa.recovery_codes = list(recovery_codes)
            mfa.verified = verified
            flag_modified(mfa, "recovery_codes")
            user.mfa = mfa
            session.add(user)

    def verify_mfa(self, user_id: str) -> bool:
        with self.session() as session:
            mfa = session.get(UserMFA, user_id)
            if mfa is None:
                return False
            mfa.verified = True
            session.add(mfa)
            return True

    def delete_mfa(self, user_id: str) -> bool:
        with self.session() as session:
            mfa = session.get(UserMFA, user_id)
            if mfa is None:
                return False
            session.delete(mfa)
            return True

    def set_permission(self, user_id: str, permission: str, value: str | bool | int) -> bool:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return False
            perms = user.permissions_rel or UserPermissions(user_id=user_id)
            if permission == "max_domains":
                perms.max_domains = int(value)
            elif permission == "max_subdomains":
                perms.max_subdomains = int(value)
            elif permission == "enabled":
                perms.admin_enabled = bool(value)
            elif permission == "invite":
                perms.feature_invite = bool(value)
            elif permission in {"account", "dns", "manage_permissions", "reports", "userdetails", "wildcards"}:
                setattr(perms, f"admin_{permission}", bool(value))
            else:
                return False
            user.permissions_rel = perms
            session.add(user)
            return True

    def add_owned_tld(self, user_id: str, tld: str) -> bool:
        clean_tld = tld.strip()
        if not clean_tld:
            return False
        with self.session() as session:
            if session.get(User, user_id) is None:
                return False
            existing = session.get(UserOwnedTLD, (user_id, clean_tld))
            if existing is None:
                session.add(UserOwnedTLD(user_id=user_id, tld=clean_tld))
            return True

    def remove_owned_tld(self, user_id: str, tld: str) -> bool:
        clean_tld = tld.strip()
        if not clean_tld:
            return False
        with self.session() as session:
            existing = session.get(UserOwnedTLD, (user_id, clean_tld))
            if existing is None:
                return False
            session.delete(existing)
            return True

    def find_users_by_email_hashes(
        self,
        email_hashes: set[str],
        normalized_hash: str,
        limit: int = 50,
    ) -> list[str]:
        with self.session() as session:
            stmt = (
                select(User.id)
                .where(
                    or_(
                        User.email_hash.in_(list(email_hashes)),
                        User.normalized_email_hash == normalized_hash,
                    ),
                )
                .limit(limit)
            )
            return list(session.scalars(stmt).all())

    def find_user_by_domain_name(self, canonical_domain: str, find_banned: bool = True) -> User | None:
        with self.session() as session:
            stmt = select(User).join(Domain, Domain.user_id == User.id).where(Domain.name == canonical_domain)
            row = session.scalars(stmt).first()
            if row is None:
                return None
            if row.banned and not find_banned:
                return None
        return self.perform_migrations(row)

    def find_user_by_api_key(self, key_hash: str) -> tuple[User | None, ApiKey | None]:
        with self.session() as session:
            ak = session.get(ApiKey, key_hash)
            if ak is None:
                return None, None
            user = session.get(User, ak.user_id)
            if user is None:
                return None, None
        return self.perform_migrations(user), ak

    def delete_api_key(self, user_id: str, key_hash: str) -> bool:
        with self.session() as session:
            stmt = select(ApiKey).where(ApiKey.id == key_hash, ApiKey.user_id == user_id)
            ak = session.scalars(stmt).first()
            if ak is None:
                return False
            session.delete(ak)
            return True

    def clear_api_keys(self, user_id: str) -> None:
        with self.session() as session:
            session.execute(delete(ApiKey).where(ApiKey.user_id == user_id))

    def count_users_created_after(self, created_timestamp: int) -> int:
        with self.session() as session:
            stmt = select(func.count()).select_from(User).where(User.created > created_timestamp)
            return int(session.scalar(stmt) or 0)

    def count_total_users(self) -> int:
        with self.session() as session:
            stmt = select(func.count()).select_from(User)
            return int(session.scalar(stmt) or 0)

    def send_discord_analytic_webhook(
        self,
        country: str,
        site_variant: Literal["canary.eepy.page", "www.eepy.page"] | str,  # noqa: PYI051
        hashed_username: str,
    ) -> None:
        start = time.time()
        requests.post(
            Environment.dc_webhook(),
            data=json.dumps(
                {
                    "content": None,
                    "embeds": [
                        {
                            "title": "New user signup",
                            "description": f":flag_{country.lower()}: **{hashed_username}** just signed up on {site_variant} from {country}! :flag_{country.lower()}:",  # noqa: E501
                            "color": 31743,
                            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        },
                    ],
                    "attachments": [],
                },
            ),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        logger.debug(time.time() - start)

    def create_user(  # noqa: C901, PLR0913, PLR0915
        self,
        *,
        username: str,
        password: str | None,
        email: str,
        language: str,
        country: dict[str, Any],
        time_signed_up: int,
        email_instance: Email,
        target_url: str,
        dont_send_email: bool = False,
        refer_code: str | None = None,
        skip_verification: bool = False,
        device_id: str | None = None,
    ) -> str:
        logger.info(f"Creating user with username {username}")
        original_username: str = username

        hashed_username: str = Encryption.sha256(username)
        lowercase_hashed_username = Encryption.sha256(username.lower())

        if email_instance.is_taken(email):
            logger.warning("Email is already taken")
            msg = "Email is already in use!"
            raise EmailException(msg)

        with self.session() as session:
            existing = session.scalars(
                select(User).where(
                    or_(
                        User.id == hashed_username,
                        User.username == lowercase_hashed_username,
                    ),
                ),
            ).first()
            if existing is not None:
                msg_0 = "Username already taken!"
                raise UsernameException(msg_0)

        clean_email: str = email.strip()
        normalized_email: str = normalize_email_address(clean_email)

        normalized_email_hash: str = self.encryption.hash_email(normalized_email)
        email_hash: str = self.encryption.hash_email(clean_email)

        referred_by_val = ""
        if refer_code:
            if self.referrals.check(refer_code):
                logger.info("User was referred")
                referred_by_val = refer_code
            else:
                logger.warning("Invalid referral code!")
                msg_1 = "Invalid referral code!"
                raise ReferralError(msg_1)

        clean_device = normalize_device_id(device_id)
        normalized_country = CountryInfo.from_raw(country).model_dump()
        now_ts = round(time.time())
        with self.session() as session:
            new_user = User(
                id=hashed_username,
                email=self.encryption.encrypt(clean_email),
                password=(None if password is None else self.encryption.create_password(password)),
                display_name=self.encryption.encrypt(original_username),
                username=lowercase_hashed_username,
                lang=language,
                country=normalized_country,
                email_hash=email_hash,
                normalized_email_hash=normalized_email_hash,
                created=int(time_signed_up),
                last_login=now_ts,
                feature_flags={},
                verified=bool(skip_verification),
                credits=200,
                invite_code="",
                banned=False,
                ban_reasons=[],
                referral_code="",
                referred_by=referred_by_val,
                referred_count=0,
                migration_version=USER_MIGRATION_VERSION,
            )
            new_user.permissions_rel = UserPermissions(
                user_id=hashed_username,
                max_domains=3,
                max_subdomains=5,
                feature_invite=False,
                admin_enabled=False,
            )
            new_user.owned_tlds_rel = [UserOwnedTLD(user_id=hashed_username, tld="eepy.page")]
            new_user.risk_profile = UserRiskProfile(
                user_id=hashed_username,
                score=0,
                locked=False,
                disabled=False,
                disable_reasons=[],
            )
            if clean_device:
                new_user.devices = [
                    UserDevice(
                        user_id=hashed_username,
                        device_id=clean_device,
                        first_seen=now_ts,
                        last_seen=now_ts,
                    ),
                ]
            session.add(new_user)

        ip = normalized_country.get("ip") or ""
        try:
            self.risk_manager.evaluate_and_update_risk(
                user_id=hashed_username,
                ip=ip,
                device_id=device_id,
                users_table=self,
            )
        except Exception:
            logger.exception("Failed to evaluate risk on signup")

        if dont_send_email:
            logger.warning(
                "Don't send info activated in create_user. This is only meant for testing environments",
            )
        elif not skip_verification and not email_instance.send_verification_code(
            target_url,
            hashed_username,
            email,
        ):
            logger.info("Failed to send verification")
            msg_2 = "Email already in use!"
            raise EmailException(msg_2)

        country_code = normalized_country.get("country")
        if country_code:
            try:
                self.send_discord_analytic_webhook(country_code, target_url, hashed_username)
            except Exception as e:
                logger.warning(e)

        return hashed_username

    def create_invite(self, user_id: str) -> str:
        logger.info("Creating invite...")
        invite_code: str = Encryption.generate_random_string(16)
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None or user.banned:
                msg = "User does not exist!"
                raise UserNotExistError(msg)

            if len(user.invites or []) >= 3:  # noqa: PLR2004
                logger.info("User has surpassed their invite limit")
                msg_0 = "Invite limit exceeded"
                raise InviteException(msg_0)

            session.add(
                Invite(
                    code=invite_code,
                    creator_id=user_id,
                    used=False,
                    used_by=None,
                    used_at=None,
                    created=round(time.time()),
                ),
            )
        return invite_code

    def get_invites(self, user_id: str) -> dict[str, InviteType]:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None or user.banned:
                msg = "Invalid user!"
                raise UserNotExistError(msg)
            return {inv.code: InviteType.model_validate(inv) for inv in (user.invites or [])}

    def get_user_gdpr(self, user_id: str) -> dict[str, Any]:
        user_data = self.get_user(user_id)

        if user_data is None:
            msg = "Invalid user"
            raise UserNotExistError(msg)

        return {
            "user_id": user_data.id,
            "location": user_data.country,
            "creation_date": user_data.created,
            "domains": [d.model_dump() for d in Domains.normalize_domains(user_data.domains)],
            "lang": user_data.lang,
            "last_login": user_data.last_login,
            "permissions": user_data.permissions_dict(),
            "verified": user_data.verified,
        }

    def get_user_profile(
        self,
        user_id: str,
        session_table: "SessionTable",
        find_banned: bool = False,
        user: User | None = None,
    ) -> UserPageType:
        logger.info(f"Getting user profile for {user_id}")
        user_data = user or self.get_user(
            user_id,
            find_banned,
        )

        if user_data is None:
            msg = "Invalid user"
            raise UserNotExistError(msg)

        now_utc = datetime.now(UTC)
        owner_hash_target = Encryption.sha256(user_id + "eepy.page")
        with session_table.session() as db_sess:
            stmt = select(SessionModel).where(
                SessionModel.expires > now_utc,
                or_(
                    SessionModel.owner_hash == owner_hash_target,
                    (SessionModel.owner == user_id) & (SessionModel.type == "refresh"),
                ),
            )
            session_rows = db_sess.scalars(stmt).all()
            session_data = [row.to_public_dict() for row in session_rows]

        return UserPageType(
            username=self.encryption.decrypt(user_data.display_name),
            email=self.encryption.decrypt(user_data.email),
            lang=user_data.lang,
            country=CountryInfo.from_raw(user_data.country),
            created=user_data.created,
            verified=user_data.verified,
            permissions=user_data.permissions_dict(),
            domains=Domains.normalize_domains(user_data.domains),
            sessions=session_data,
            invites={inv.code: InviteType.model_validate(inv) for inv in (user_data.invites or [])},
            mfa_enabled=user_data.mfa_verified,
            referral_code=user_data.referral_code or None,
            referred_people=user_data.referred_count,
            owned_tlds=user_data.owned_tlds,
        )

    def mark_deletion_pending(self, userid: str, reasons: list[str]) -> None:
        with self.session() as session:
            user = session.get(User, userid)
            if user is not None:
                user.banned = True
                user.deleted_in = datetime.now(UTC) + timedelta(weeks=52)
                current_reasons = list(user.ban_reasons or [])
                current_reasons.extend(reasons)
                user.ban_reasons = current_reasons
                flag_modified(user, "ban_reasons")
                session.add(user)

    def reinstate_user(self, user_id: str) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is not None:
                user.banned = False
                user.unbanned = round(time.time())
                user.deleted_in = None
                session.add(user)

    def record_login(self, user_id: str, ip: str) -> None:
        now_ts = round(time.time())
        clean_ip = ip.strip() if ip else ""
        with self.session() as session:
            user = session.get(User, user_id)
            if user is not None:
                user.last_login = now_ts
                session.add(user)
                if clean_ip:
                    existing_ip = session.get(UserIP, (user_id, clean_ip))
                    if existing_ip is not None:
                        existing_ip.last_seen = now_ts
                        session.add(existing_ip)
                    else:
                        session.add(
                            UserIP(
                                user_id=user_id,
                                ip=clean_ip,
                                first_seen=now_ts,
                                last_seen=now_ts,
                            ),
                        )

    def update_display_name(self, user_id: str, encrypted_display_name: str, username_hash: str) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is not None:
                user.display_name = encrypted_display_name
                user.username = username_hash
                session.add(user)

    def grant_full_admin(self, user_id: str, max_limit: int) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is not None:
                perms = user.permissions_rel or UserPermissions(user_id=user_id)
                perms.admin_enabled = True
                perms.admin_account = True
                perms.admin_dns = True
                perms.admin_manage_permissions = True
                perms.admin_reports = True
                perms.admin_userdetails = True
                perms.admin_wildcards = True
                perms.max_domains = max_limit
                perms.max_subdomains = max_limit
                perms.feature_invite = True
                user.permissions_rel = perms
                session.add(user)

    def restore_login_metadata(self, user_id: str, metadata: Mapping[str, Any]) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is not None:
                raw_ips = metadata.get("accessed_from")
                if isinstance(raw_ips, list):
                    seen: set[str] = set()
                    restored_ips: list[UserIP] = []
                    for idx, ip_val in enumerate(raw_ips):
                        ip_str = str(ip_val).strip()
                        if not ip_str or ip_str in seen:
                            continue
                        seen.add(ip_str)
                        restored_ips.append(
                            UserIP(user_id=user_id, ip=ip_str, first_seen=idx, last_seen=idx),
                        )
                    user.ips = restored_ips
                else:
                    user.ips = []

                if "last_login" in metadata and metadata["last_login"] is not None:
                    user.last_login = int(metadata["last_login"])
                else:
                    user.last_login = 0
                session.add(user)

    def find_flagged_users(self, flagged_threshold: int) -> list[User]:
        with self.session() as session:
            stmt = (
                select(User)
                .join(UserRiskProfile, UserRiskProfile.user_id == User.id)
                .where(
                    or_(
                        UserRiskProfile.score >= flagged_threshold,
                        UserRiskProfile.disabled.is_(True),
                    ),
                )
            )
            rows = list(session.scalars(stmt).all())
        return [self.perform_migrations(row) for row in rows]

    def update_user_risk_fields(
        self,
        user_id: str,
        *,
        score: int | None = None,
        locked: bool | None = None,
        clear_flags: bool = False,
    ) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return
            rp = user.risk_profile or UserRiskProfile(user_id=user_id)
            if clear_flags:
                user.alt_links = []
                if score is None:
                    rp.score = 0
            if score is not None:
                rp.score = min(100, max(0, score))
            if locked is not None:
                rp.locked = locked
            user.risk_profile = rp
            session.add(user)

    def set_user_disabled(
        self,
        user_id: str,
        *,
        disabled: bool,
        reason: str | None = None,
    ) -> None:
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return
            rp = user.risk_profile or UserRiskProfile(user_id=user_id)
            if disabled:
                rp.disabled = True
                clean_reason = reason.strip() if reason else ""
                if clean_reason:
                    reasons = list(rp.disable_reasons or [])
                    if clean_reason not in reasons:
                        reasons.append(clean_reason)
                    rp.disable_reasons = reasons
                    flag_modified(rp, "disable_reasons")
            else:
                rp.disabled = False
                rp.disable_reasons = []
                flag_modified(rp, "disable_reasons")
                rp.locked = True
                rp.score = 0
                user.alt_links = []
            user.risk_profile = rp
            session.add(user)

    def save_evaluated_risk(
        self,
        user_id: str,
        risk_data: UserRisk,
        *,
        only_if_unlocked: bool = True,
    ) -> None:
        now_ts = round(time.time())
        with self.session() as session:
            user = session.get(User, user_id)
            if user is None:
                return
            rp = user.risk_profile or UserRiskProfile(user_id=user_id)
            if only_if_unlocked and rp.locked:
                return

            rp.score = int(risk_data.get("score") or 0)
            rp.locked = bool(risk_data.get("locked", False))
            rp.disabled = bool(risk_data.get("disabled", False))
            rp.disable_reasons = list(risk_data.get("disable_reasons") or [])
            flag_modified(rp, "disable_reasons")
            user.risk_profile = rp

            clean_dev = normalize_device_id(risk_data.get("device_id"))
            if clean_dev:
                existing_dev = session.get(UserDevice, (user_id, clean_dev))
                if existing_dev is not None:
                    existing_dev.last_seen = now_ts
                    session.add(existing_dev)
                else:
                    user.devices.append(
                        UserDevice(
                            user_id=user_id,
                            device_id=clean_dev,
                            first_seen=now_ts,
                            last_seen=now_ts,
                        ),
                    )

            new_links: list[AltLink] = []
            for signal_type, flag_data in (risk_data.get("flags") or {}).items():
                related_uid_raw = flag_data.get("user_id")
                related_uid = str(related_uid_raw) if related_uid_raw else None
                if related_uid is not None and session.get(User, related_uid) is None:
                    continue
                exp_val = flag_data.get("expires_at")
                new_links.append(
                    AltLink(
                        user_id=user_id,
                        related_user_id=related_uid,
                        signal_type=str(signal_type),
                        score=int(flag_data.get("score") or 0),
                        reason=str(flag_data.get("reason") or ""),
                        detected_at=int(flag_data.get("detected_at") or 0),
                        expires_at=int(exp_val) if exp_val is not None else None,
                        permanent=bool(flag_data.get("permanent", False)),
                    ),
                )
            user.alt_links = new_links
            session.add(user)

    def perform_migrations(self, user: User) -> User:
        """Runs registered in-backend migrations for a user record."""
        current_version = int(user.migration_version or 0)
        if current_version >= USER_MIGRATION_VERSION and not USER_MIGRATIONS:
            return user

        if current_version < USER_MIGRATION_VERSION:
            with self.session() as session:
                user_row = session.get(User, user.id)
                if user_row is None:
                    return user

                for target_ver in range(current_version + 1, USER_MIGRATION_VERSION + 1):
                    migration_fn = USER_MIGRATIONS.get(target_ver)
                    if migration_fn is not None:
                        migration_fn(user_row, self)

                user_row.migration_version = USER_MIGRATION_VERSION
                session.add(user_row)
                session.flush()
                return user_row

        return user

    def find_username_case_collisions(self) -> dict[str, list[str]]:
        by_lower_hash: dict[str, list[str]] = {}
        with self.session() as session:
            for user in session.scalars(select(User)).all():
                lower_hash = user.username
                if not lower_hash and user.display_name:
                    try:
                        decrypted = self.encryption.decrypt(user.display_name).strip()
                        if decrypted:
                            lower_hash = Encryption.sha256(decrypted.lower())
                    except Exception:  # noqa: S112
                        continue
                if lower_hash:
                    by_lower_hash.setdefault(lower_hash, []).append(user.id)

        return {h: ids for h, ids in by_lower_hash.items() if len(ids) > 1}

    def migrate_all_users(self) -> None:
        logger.info("Starting background user migrations...")
        count = 0
        with self.session() as session:
            unmigrated_ids = list(
                session.scalars(
                    select(User.id).where(User.migration_version != USER_MIGRATION_VERSION),
                ).all(),
            )

        for user_id in unmigrated_ids:
            try:
                user_data = self.get_by_id(user_id)
                if isinstance(user_data, User):
                    self.perform_migrations(user_data)
                    count += 1
            except Exception:
                logger.exception(f"Failed to migrate user {user_id}")

        logger.info(f"Finished user migrations for {count} users.")

    def delete_unverified_users(self, days: int = 7) -> int:
        cutoff = int(time.time()) - (days * 86400)
        with self.session() as session:
            stmt = delete(User).where(
                User.verified.is_(False),
                User.created < cutoff,
            )
            result = session.execute(stmt)
            deleted = rowcount(result)

        if deleted > 0:
            logger.info(f"Deleted {deleted} accounts that have been unverified for >={days} days")
        else:
            logger.debug("delete_unverified_users: No eligible accounts found for deletion")

        return deleted

    def start_unverified_purge_loop(self, interval: int = 3600) -> None:
        logger.info(f"Starting unverified account deletion thread (checks every {interval}s)")

        while True:
            try:
                self.delete_unverified_users()
            except Exception:
                logger.exception("Failed during unverified account purge run")

            time.sleep(interval)
