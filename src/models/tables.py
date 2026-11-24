from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import JSON, BigInteger, Column, DateTime, Index, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from dns_.types import get_record_type

if TYPE_CHECKING:
    from database.tables.status import StatusType
    from models.domain import DomainRecord


class User(SQLModel, table=True):
    # note on all # pyright: ignore[reportAssignmentType] comments on __tablename__ assignments:
    # this is not actually an issue being suppressed, it's simply a SQLModel problem

    __tablename__ = "users"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (Index("ix_users_verified_created", "verified", "created"),)

    id: str = Field(primary_key=True)
    email: str = Field(default="")
    email_hash: str | None = Field(default=None, index=True)
    normalized_email_hash: str | None = Field(default=None, index=True)
    password: str | None = Field(default=None)
    display_name: str = Field(default="")
    username: str | None = Field(default=None, index=True)
    lang: str = Field(default="en")
    country: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}"),
    )
    created: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0", index=True),
    )
    last_login: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    feature_flags: dict[str, bool] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}"),
    )
    verified: bool = Field(default=False, index=True)
    credits: int = Field(default=200)
    beta_enroll: bool = Field(default=False)
    beta_updated: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    invite_code: str = Field(default="")
    banned: bool = Field(default=False, index=True)
    ban_reasons: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )
    unbanned: int | None = Field(
        default=None,
        sa_column=Column(BigInteger, nullable=True),
    )
    deleted_in: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True, index=True),
    )
    referral_code: str = Field(default="", index=True)
    referred_by: str = Field(default="", index=True)
    referred_count: int = Field(default=0)
    migration_version: int = Field(default=1, index=True)
    extra_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}"),
    )

    permissions_rel: Optional["UserPermissions"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
        },
    )
    mfa: Optional["UserMFA"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
        },
    )
    ips: list["UserIP"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    owned_tlds_rel: list["UserOwnedTLD"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    risk_profile: Optional["UserRiskProfile"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
        },
    )
    devices: list["UserDevice"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    alt_links: list["AltLink"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
            "foreign_keys": "[AltLink.user_id]",
        },
    )
    incoming_alt_links: list["AltLink"] = Relationship(
        back_populates="related_user",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
            "foreign_keys": "[AltLink.related_user_id]",
        },
    )
    domains: list["Domain"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    tunnels: list["ServeoTunnel"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    api_keys: list["ApiKey"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )
    invites: list["Invite"] = Relationship(
        back_populates="creator",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "lazy": "selectin",
            "foreign_keys": "[Invite.creator_id]",
        },
    )

    def _build_risk_dict(self) -> dict[str, Any]:
        flags: dict[str, dict[str, Any]] = {}
        for link in sorted(self.alt_links or [], key=lambda item: (item.detected_at, item.score)):
            flags[link.signal_type] = link.to_flag_dict()

        sorted_devices = sorted(self.devices or [], key=lambda d: d.last_seen, reverse=True)
        latest_device_id = sorted_devices[0].device_id if sorted_devices else None

        if self.risk_profile is not None:
            return {
                "score": self.risk_profile.score,
                "locked": self.risk_profile.locked,
                "disabled": self.risk_profile.disabled,
                "disable_reasons": list(self.risk_profile.disable_reasons or []),
                "flags": flags,
                "device_id": latest_device_id,
            }

        return {
            "score": 0,
            "locked": False,
            "disabled": False,
            "disable_reasons": [],
            "flags": flags,
            "device_id": latest_device_id,
        }

    def to_dict(self) -> dict[str, Any]:  # noqa: C901
        perms_dict = (
            self.permissions_rel.to_dict() if self.permissions_rel is not None else UserPermissions.default_dict()
        )
        sorted_ips = sorted(self.ips or [], key=lambda r: (r.first_seen, r.ip))
        owned_tlds = [row.tld for row in (self.owned_tlds_rel or [])]

        result: dict[str, Any] = {
            "_id": self.id,
            "email": self.email,
            "password": self.password,
            "display_name": self.display_name,
            "lang": self.lang,
            "country": dict(self.country) if isinstance(self.country, Mapping) else {},
            "accessed_from": [row.ip for row in sorted_ips],
            "created": self.created,
            "last_login": self.last_login,
            "permissions": perms_dict,
            "feature_flags": dict(self.feature_flags) if isinstance(self.feature_flags, Mapping) else {},
            "verified": self.verified,
            "domains": [d.to_record() for d in (self.domains or [])],
            "api_keys": {k.id: k.to_dict() for k in (self.api_keys or [])},
            "credits": self.credits,
            "beta_enroll": self.beta_enroll,
            "beta_updated": self.beta_updated,
            "invites": {inv.code: inv.to_dict() for inv in (self.invites or [])},
            "invite_code": self.invite_code,
            "banned": self.banned,
            "ban_reasons": list(self.ban_reasons or []),
            "referral_code": self.referral_code,
            "referred_by": self.referred_by,
            "referred_count": self.referred_count,
            "owned_tlds": owned_tlds,
            "risk": self._build_risk_dict(),
            "migration_version": self.migration_version,
        }
        if self.mfa is not None:
            result["totp"] = self.mfa.to_dict()
        if self.username:
            result["username"] = self.username
        if self.email_hash:
            result["email_hash"] = self.email_hash
        if self.normalized_email_hash:
            result["normalized_email_hash"] = self.normalized_email_hash
        if self.tunnels:
            result["tunnels"] = [t.to_embedded_dict() for t in self.tunnels]
        if self.unbanned is not None:
            result["unbanned"] = self.unbanned
        if self.deleted_in is not None:
            result["deleted_in"] = self.deleted_in
        if isinstance(self.extra_data, Mapping):
            for k, v in self.extra_data.items():
                if k not in result:
                    result[k] = v
        return result


class UserPermissions(SQLModel, table=True):
    __tablename__ = "user_permissions"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    max_domains: int = Field(default=3)
    max_subdomains: int = Field(default=5)
    feature_invite: bool = Field(default=False)
    admin_enabled: bool = Field(default=False, index=True)
    admin_account: bool = Field(default=False)
    admin_dns: bool = Field(default=False)
    admin_manage_permissions: bool = Field(default=False)
    admin_reports: bool = Field(default=False)
    admin_userdetails: bool = Field(default=False)
    admin_wildcards: bool = Field(default=False)

    user: User | None = Relationship(back_populates="permissions_rel")

    @staticmethod
    def default_dict() -> dict[str, Any]:
        return {
            "admin": {
                "enabled": False,
                "permissions": {},
            },
            "limits": {
                "max_domains": 3,
                "max_subdomains": 5,
            },
            "features": {
                "invite": False,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        admin_perms = {
            "account": self.admin_account,
            "dns": self.admin_dns,
            "manage_permissions": self.admin_manage_permissions,
            "reports": self.admin_reports,
            "userdetails": self.admin_userdetails,
            "wildcards": self.admin_wildcards,
        }
        return {
            "admin": {
                "enabled": self.admin_enabled,
                "permissions": {k: v for k, v in admin_perms.items() if v},
            },
            "limits": {
                "max_domains": self.max_domains,
                "max_subdomains": self.max_subdomains,
            },
            "features": {
                "invite": self.feature_invite,
            },
        }

    def apply_dict(self, data: Mapping[str, Any]) -> None:
        limits = data.get("limits")
        if isinstance(limits, Mapping):
            if limits.get("max_domains") is not None:
                self.max_domains = int(limits["max_domains"])
            if limits.get("max_subdomains") is not None:
                self.max_subdomains = int(limits["max_subdomains"])
        features = data.get("features")
        if isinstance(features, Mapping) and "invite" in features:
            self.feature_invite = bool(features["invite"])
        admin = data.get("admin")
        if isinstance(admin, Mapping):
            if "enabled" in admin:
                self.admin_enabled = bool(admin["enabled"])
            perms = admin.get("permissions")
            if isinstance(perms, Mapping):
                self.admin_account = bool(perms.get("account", False))
                self.admin_dns = bool(perms.get("dns", False))
                self.admin_manage_permissions = bool(perms.get("manage_permissions", False))
                self.admin_reports = bool(perms.get("reports", False))
                self.admin_userdetails = bool(perms.get("userdetails", False))
                self.admin_wildcards = bool(perms.get("wildcards", False))


class UserMFA(SQLModel, table=True):
    __tablename__ = "user_mfa"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    verified: bool = Field(default=False)
    secret_key: str = Field(default="")
    recovery_codes: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )

    user: User | None = Relationship(back_populates="mfa")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "key": self.secret_key,
            "recovery": list(self.recovery_codes or []),
        }


class UserIP(SQLModel, table=True):
    __tablename__ = "user_ips"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    ip: str = Field(primary_key=True, index=True)
    first_seen: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    last_seen: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    user: User | None = Relationship(back_populates="ips")


class UserOwnedTLD(SQLModel, table=True):
    __tablename__ = "user_owned_tlds"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    tld: str = Field(primary_key=True, index=True)

    user: User | None = Relationship(back_populates="owned_tlds_rel")


class UserRiskProfile(SQLModel, table=True):
    __tablename__ = "user_risk_profiles"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    score: int = Field(default=0, index=True)
    locked: bool = Field(default=False)
    disabled: bool = Field(default=False, index=True)
    disable_reasons: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )

    user: User | None = Relationship(back_populates="risk_profile")


class UserDevice(SQLModel, table=True):
    __tablename__ = "user_devices"  # pyright: ignore[reportAssignmentType]

    user_id: str = Field(primary_key=True, foreign_key="users.id", ondelete="CASCADE")
    device_id: str = Field(primary_key=True, index=True)
    first_seen: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    last_seen: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0", index=True),
    )

    user: User | None = Relationship(back_populates="devices")


class AltLink(SQLModel, table=True):
    __tablename__ = "alt_links"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (
        Index("ix_alt_links_user_signal", "user_id", "signal_type"),
        Index("ix_alt_links_user_related", "user_id", "related_user_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    related_user_id: str | None = Field(default=None, foreign_key="users.id", index=True, ondelete="CASCADE")
    signal_type: str = Field(index=True)
    score: int = Field(default=0)
    reason: str = Field(default="")
    detected_at: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    expires_at: int | None = Field(
        default=None,
        sa_column=Column(BigInteger, nullable=True, index=True),
    )
    permanent: bool = Field(default=False)

    user: User | None = Relationship(
        back_populates="alt_links",
        sa_relationship_kwargs={"foreign_keys": "[AltLink.user_id]"},
    )
    related_user: User | None = Relationship(
        back_populates="incoming_alt_links",
        sa_relationship_kwargs={"foreign_keys": "[AltLink.related_user_id]"},
    )

    def to_flag_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "score": self.score,
            "reason": self.reason,
            "detected_at": self.detected_at,
            "permanent": self.permanent,
        }
        if self.expires_at is not None:
            payload["expires_at"] = self.expires_at
        if self.related_user_id is not None:
            payload["user_id"] = self.related_user_id
        return payload


class Domain(SQLModel, table=True):
    __tablename__ = "domains"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (
        UniqueConstraint("user_id", "name", "type", name="uq_domains_user_name_type"),
        Index("ix_domains_name_type", "name", "type"),
    )

    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    name: str = Field(index=True)
    type: str = Field(index=True)
    ip: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )
    registered: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    user: User | None = Relationship(back_populates="domains")

    def to_record(self) -> "DomainRecord":
        return {
            "name": self.name,
            "type": get_record_type(self.type),
            "ip": list(self.ip) if isinstance(self.ip, list) else [str(self.ip)],
            "registered": self.registered,
        }


class ServeoTunnel(SQLModel, table=True):
    __tablename__ = "serveo_tunnels"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    serveo_auth_record: str = Field(default="")
    ssh_fingerprint: str = Field(default="")
    subdomain: str = Field(default="")
    hostname: str = Field(default="", index=True)
    service: str = Field(default="")
    local_port: int = Field(default=80)
    command: str = Field(default="")
    created_at: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    updated_at: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    user: User | None = Relationship(back_populates="tunnels")

    def to_record(self) -> dict[str, Any]:
        return {
            "_id": self.id,
            "id": self.id,
            "user_id": self.user_id,
            "serveo_auth_record": self.serveo_auth_record,
            "ssh_fingerprint": self.ssh_fingerprint,
            "subdomain": self.subdomain,
            "hostname": self.hostname,
            "service": self.service,
            "local_port": self.local_port,
            "command": self.command,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_embedded_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "serveo_auth_record": self.serveo_auth_record,
            "ssh_fingerprint": self.ssh_fingerprint,
            "subdomain": self.subdomain,
            "hostname": self.hostname,
            "service": self.service,
            "local_port": self.local_port,
            "command": self.command,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ApiKey(SQLModel, table=True):
    __tablename__ = "api_keys"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    string: str = Field(default="")
    perms: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )
    domains: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False, server_default="[]"),
    )
    comment: str = Field(default="")

    user: User | None = Relationship(back_populates="api_keys")

    def to_dict(self) -> dict[str, Any]:
        return {
            "string": self.string,
            "perms": list(self.perms or []),
            "domains": list(self.domains or []),
            "comment": self.comment,
        }


class Invite(SQLModel, table=True):
    __tablename__ = "invites"  # pyright: ignore[reportAssignmentType]

    code: str = Field(primary_key=True)
    creator_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    used: bool = Field(default=False, index=True)
    used_by: str | None = Field(default=None)
    used_at: int | None = Field(
        default=None,
        sa_column=Column(BigInteger, nullable=True),
    )
    created: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    creator: User | None = Relationship(
        back_populates="invites",
        sa_relationship_kwargs={"foreign_keys": "[Invite.creator_id]"},
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "used_by": self.used_by,
            "used_at": self.used_at,
            "created": self.created,
        }


class SessionModel(SQLModel, table=True):
    __tablename__ = "sessions"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    owner: str = Field(default="", index=True)
    owner_hash: str | None = Field(default=None, index=True)
    type: str = Field(default="access", index=True)
    created: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    expires: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )
    agent: str = Field(default="")
    ip: str = Field(default="")
    parent: str | None = Field(default=None, index=True)
    manual_login: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
    )

    def to_dict(self) -> dict[str, Any]:
        expires_dt = self.expires
        if expires_dt is not None and expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=UTC)
        payload: dict[str, Any] = {
            "_id": self.id,
            "owner": self.owner,
            "type": self.type,
            "created": self.created,
            "expires": expires_dt,
            "agent": self.agent,
            "ip": self.ip,
        }
        if self.owner_hash:
            payload["owner_hash"] = self.owner_hash
        if self.parent:
            payload["parent"] = self.parent
        if self.manual_login is not None:
            payload["manual_login"] = self.manual_login
        return payload


class VerificationCode(SQLModel, table=True):
    __tablename__ = "codes"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    type: str = Field(index=True)
    account: str = Field(default="")
    expire: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0", index=True),
    )
    expires_after: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )

    def to_dict(self) -> dict[str, Any]:
        exp_after = self.expires_after
        if exp_after is not None and exp_after.tzinfo is None:
            exp_after = exp_after.replace(tzinfo=UTC)
        return {
            "_id": self.id,
            "type": self.type,
            "account": self.account,
            "expire": self.expire,
            "expires_after": exp_after,
        }


class Reward(SQLModel, table=True):
    __tablename__ = "rewards"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    created: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )
    mappings: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False, server_default="{}"),
    )
    associated_email: str = Field(default="")
    email_hash: str = Field(default="", index=True)
    used: bool = Field(default=False, index=True)
    used_by: str | None = Field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "_id": self.id,
            "created": self.created,
            "mappings": dict(self.mappings) if isinstance(self.mappings, Mapping) else {},
            "associated_email": self.associated_email,
            "email_hash": self.email_hash,
            "used": self.used,
            "used_by": self.used_by,
        }


class Referral(SQLModel, table=True):
    __tablename__ = "referrals"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    owner: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    created: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    redemptions: list["ReferralRedemption"] = Relationship(
        back_populates="referral",
        sa_relationship_kwargs={"cascade": "all, delete-orphan", "lazy": "selectin"},
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "_id": self.id,
            "owner": self.owner,
            "users": [r.referred_user_id for r in (self.redemptions or [])],
            "created": self.created,
        }


class ReferralRedemption(SQLModel, table=True):
    __tablename__ = "referral_redemptions"  # pyright: ignore[reportAssignmentType]

    id: int | None = Field(default=None, primary_key=True)
    referral_id: str = Field(foreign_key="referrals.id", index=True, ondelete="CASCADE")
    referred_user_id: str = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    created_at: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0"),
    )

    referral: Referral | None = Relationship(back_populates="redemptions")


class StatusModel(SQLModel, table=True):
    __tablename__ = "status"  # pyright: ignore[reportAssignmentType]

    id: str = Field(primary_key=True)
    time: float = Field(default=0.0)
    message: str = Field(default="")
    active: bool = Field(default=True, index=True)

    def to_dict(self) -> "StatusType":
        return {
            "_id": self.id,
            "time": self.time,
            "message": self.message,
            "active": self.active,
        }


class IPActivityModel(SQLModel, table=True):
    __tablename__ = "ip_activity"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (Index("ix_ip_activity_ip_last_seen", "ip", "last_seen"),)

    id: str = Field(primary_key=True)
    ip: str = Field(default="", index=True)
    user_id: str = Field(default="", index=True)
    last_seen: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0", index=True),
    )
    expires_after: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )

    def to_dict(self) -> dict[str, Any]:
        exp_after = self.expires_after
        if exp_after is not None and exp_after.tzinfo is None:
            exp_after = exp_after.replace(tzinfo=UTC)
        return {
            "_id": self.id,
            "ip": self.ip,
            "user_id": self.user_id,
            "last_seen": self.last_seen,
            "expires_after": exp_after,
        }


class RecentLogoutModel(SQLModel, table=True):
    __tablename__ = "recent_logouts"  # pyright: ignore[reportAssignmentType]

    id: int | None = Field(default=None, primary_key=True)
    user_id: str = Field(default="", index=True)
    ip: str | None = Field(default=None, index=True)
    device_id: str | None = Field(default=None, index=True)
    time: int = Field(
        default=0,
        sa_column=Column(BigInteger, nullable=False, server_default="0", index=True),
    )
    expires_after: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )

    def to_dict(self) -> dict[str, Any]:
        exp_after = self.expires_after
        if exp_after is not None and exp_after.tzinfo is None:
            exp_after = exp_after.replace(tzinfo=UTC)
        return {
            "_id": self.id,
            "user_id": self.user_id,
            "ip": self.ip,
            "device_id": self.device_id,
            "time": self.time,
            "expires_after": exp_after,
        }
