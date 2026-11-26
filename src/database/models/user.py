from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base

if TYPE_CHECKING:
    from database.models.api import ApiKey
    from database.models.domain import Domain
    from database.models.invite import Invite
    from database.models.serveo import ServeoTunnel
    from security.risk import RiskFlag, UserRisk


class User(Base):
    __tablename__ = "users"
    __table_args__ = (Index("ix_users_verified_created", "verified", "created"),)

    id: Mapped[str] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(default="")
    email_hash: Mapped[str | None] = mapped_column(default=None, unique=True, index=True)
    normalized_email_hash: Mapped[str | None] = mapped_column(default=None, unique=True, index=True)
    password: Mapped[str | None] = mapped_column(default=None)
    display_name: Mapped[str] = mapped_column(default="")
    username: Mapped[str | None] = mapped_column(default=None, unique=True, index=True)
    lang: Mapped[str] = mapped_column(default="en")
    country: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default_factory=dict, server_default="{}")
    created: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0", index=True)
    last_login: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    feature_flags: Mapped[dict[str, bool]] = mapped_column(
        JSON,
        nullable=False,
        default_factory=dict,
        server_default="{}",
    )
    verified: Mapped[bool] = mapped_column(default=False, index=True)
    credits: Mapped[int] = mapped_column(default=200)
    invite_code: Mapped[str] = mapped_column(default="")
    banned: Mapped[bool] = mapped_column(default=False, index=True)
    ban_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")
    unbanned: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    deleted_in: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
    )
    referral_code: Mapped[str] = mapped_column(default="", index=True)
    referred_by: Mapped[str] = mapped_column(default="", index=True)
    referred_count: Mapped[int] = mapped_column(default=0)
    migration_version: Mapped[int] = mapped_column(default=1, index=True)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default_factory=dict, server_default="{}")

    # passive_deletes=True delegates child row cleanup to Postgres ON DELETE CASCADE FKs.
    permissions_rel: Mapped[UserPermissions | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default=None,
    )
    mfa: Mapped[UserMFA | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default=None,
    )
    ips: Mapped[list[UserIP]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    owned_tlds_rel: Mapped[list[UserOwnedTLD]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    risk_profile: Mapped[UserRiskProfile | None] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default=None,
    )
    devices: Mapped[list[UserDevice]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    alt_links: Mapped[list[AltLink]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        foreign_keys="[AltLink.user_id]",
        default_factory=list,
    )
    incoming_alt_links: Mapped[list[AltLink]] = relationship(
        back_populates="related_user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        foreign_keys="[AltLink.related_user_id]",
        default_factory=list,
    )
    domains: Mapped[list[Domain]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    tunnels: Mapped[list[ServeoTunnel]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        default_factory=list,
    )
    invites: Mapped[list[Invite]] = relationship(
        back_populates="creator",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        foreign_keys="[Invite.creator_id]",
        default_factory=list,
    )

    @property
    def owned_tlds(self) -> list[str]:
        return [row.tld for row in (self.owned_tlds_rel or [])]

    @property
    def is_disabled(self) -> bool:
        return bool(self.risk_profile and self.risk_profile.disabled)

    @property
    def is_admin(self) -> bool:
        return bool(self.permissions_rel and self.permissions_rel.admin_enabled)

    @property
    def mfa_verified(self) -> bool:
        return bool(self.mfa and self.mfa.verified)

    @property
    def accessed_ips(self) -> list[str]:
        sorted_ips = sorted(self.ips or [], key=lambda r: (r.first_seen, r.ip))
        return [row.ip for row in sorted_ips]

    def permissions_dict(self) -> dict[str, Any]:
        if self.permissions_rel is not None:
            return self.permissions_rel.to_dict()
        return UserPermissions.default_dict()

    def risk_dict(self) -> UserRisk:
        flags: dict[str, RiskFlag] = {}
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


class UserPermissions(Base):
    __tablename__ = "user_permissions"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    max_domains: Mapped[int] = mapped_column(default=3)
    max_subdomains: Mapped[int] = mapped_column(default=5)
    feature_invite: Mapped[bool] = mapped_column(default=False)
    admin_enabled: Mapped[bool] = mapped_column(default=False, index=True)
    admin_account: Mapped[bool] = mapped_column(default=False)
    admin_dns: Mapped[bool] = mapped_column(default=False)
    admin_manage_permissions: Mapped[bool] = mapped_column(default=False)
    admin_reports: Mapped[bool] = mapped_column(default=False)
    admin_userdetails: Mapped[bool] = mapped_column(default=False)
    admin_wildcards: Mapped[bool] = mapped_column(default=False)

    user: Mapped[User | None] = relationship(
        back_populates="permissions_rel",
        default=None,
        repr=False,
        compare=False,
    )

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


class UserMFA(Base):
    __tablename__ = "user_mfa"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    verified: Mapped[bool] = mapped_column(default=False)
    secret_key: Mapped[str] = mapped_column(default="")
    recovery_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")

    user: Mapped[User | None] = relationship(back_populates="mfa", default=None, repr=False, compare=False)


class UserIP(Base):
    __tablename__ = "user_ips"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    ip: Mapped[str] = mapped_column(primary_key=True, index=True)
    first_seen: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_seen: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    user: Mapped[User | None] = relationship(back_populates="ips", default=None, repr=False, compare=False)


class UserOwnedTLD(Base):
    __tablename__ = "user_owned_tlds"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    tld: Mapped[str] = mapped_column(primary_key=True, index=True)

    user: Mapped[User | None] = relationship(
        back_populates="owned_tlds_rel",
        default=None,
        repr=False,
        compare=False,
    )


class UserRiskProfile(Base):
    __tablename__ = "user_risk_profiles"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    score: Mapped[int] = mapped_column(default=0, index=True)
    locked: Mapped[bool] = mapped_column(default=False)
    disabled: Mapped[bool] = mapped_column(default=False, index=True)
    disable_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default_factory=list, server_default="[]")

    user: Mapped[User | None] = relationship(back_populates="risk_profile", default=None, repr=False, compare=False)


class UserDevice(Base):
    __tablename__ = "user_devices"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    device_id: Mapped[str] = mapped_column(primary_key=True, index=True)
    first_seen: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_seen: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0", index=True)

    user: Mapped[User | None] = relationship(back_populates="devices", default=None, repr=False, compare=False)


class AltLink(Base):
    __tablename__ = "alt_links"
    __table_args__ = (
        Index("ix_alt_links_user_signal", "user_id", "signal_type"),
        Index("ix_alt_links_user_related", "user_id", "related_user_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, init=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    signal_type: Mapped[str] = mapped_column(index=True)
    related_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        default=None,
        index=True,
    )
    score: Mapped[int] = mapped_column(default=0)
    reason: Mapped[str] = mapped_column(default="")
    detected_at: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None, index=True)
    permanent: Mapped[bool] = mapped_column(default=False)

    user: Mapped[User | None] = relationship(
        back_populates="alt_links",
        foreign_keys="[AltLink.user_id]",
        default=None,
        repr=False,
        compare=False,
    )
    related_user: Mapped[User | None] = relationship(
        back_populates="incoming_alt_links",
        foreign_keys="[AltLink.related_user_id]",
        default=None,
        repr=False,
        compare=False,
    )

    def to_flag_dict(self) -> RiskFlag:
        payload: RiskFlag = {
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
