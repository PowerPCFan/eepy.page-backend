import logging
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import Session, delete, select

from database.exceptions import FilterMatchError
from database.session import create_db_engine, get_engine, session_scope
from dns_.types import get_record_type
from models.tables import (
    AltLink,
    ApiKey,
    Domain,
    Invite,
    IPActivityModel,
    RecentLogoutModel,
    Referral,
    ReferralRedemption,
    Reward,
    ServeoTunnel,
    SessionModel,
    StatusModel,
    User,
    UserDevice,
    UserIP,
    UserMFA,
    UserOwnedTLD,
    UserPermissions,
    UserRiskProfile,
    VerificationCode,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger: logging.Logger = logging.getLogger("eepy.page")

USER_FIELD_MAP: dict[str, str] = {
    "_id": "id",
    "id": "id",
    "email": "email",
    "email_hash": "email_hash",
    "normalized_email_hash": "normalized_email_hash",
    "password": "password",
    "display_name": "display_name",
    "username": "username",
    "lang": "lang",
    "country": "country",
    "created": "created",
    "last_login": "last_login",
    "feature_flags": "feature_flags",
    "verified": "verified",
    "credits": "credits",
    "beta_enroll": "beta_enroll",
    "beta_updated": "beta_updated",
    "invite_code": "invite_code",
    "banned": "banned",
    "ban_reasons": "ban_reasons",
    "unbanned": "unbanned",
    "deleted_in": "deleted_in",
    "referral_code": "referral_code",
    "referred_by": "referred_by",
    "referred_count": "referred_count",
    "migration_version": "migration_version",
}

TABLE_MODEL_MAP: dict[str, type[Any]] = {
    "eepy.page": User,
    "users": User,
    "user_permissions": UserPermissions,
    "user_mfa": UserMFA,
    "user_ips": UserIP,
    "user_owned_tlds": UserOwnedTLD,
    "user_risk_profiles": UserRiskProfile,
    "user_devices": UserDevice,
    "alt_links": AltLink,
    "domains": Domain,
    "serveo_tunnels": ServeoTunnel,
    "api_keys": ApiKey,
    "invites": Invite,
    "sessions": SessionModel,
    "codes": VerificationCode,
    "rewards": Reward,
    "referrals": Referral,
    "referral_redemptions": ReferralRedemption,
    "status": StatusModel,
    "ip_activity": IPActivityModel,
    "recent_logouts": RecentLogoutModel,
}


def _canonical_domain(domain: str) -> str:
    cleaned = domain.removesuffix(".").lower()
    for tld in ("eepy.page", "worksonmymachine.top"):
        if cleaned.endswith(tld):
            return cleaned
    return f"{cleaned}.eepy.page"


def _normalize_domain_list(domains_raw: object) -> list[dict[str, Any]]:
    if not domains_raw:
        return []
    normalized: list[dict[str, Any]] = []
    if isinstance(domains_raw, list):
        for item in domains_raw:
            if not isinstance(item, Mapping) or not item.get("name"):
                continue
            ip_val = item.get("ip", [])
            normalized.append(
                {
                    "name": _canonical_domain(str(item["name"])),
                    "type": get_record_type(str(item.get("type", "A")).upper()),
                    "ip": list(ip_val) if isinstance(ip_val, list) else [str(ip_val)],
                    "registered": int(item.get("registered", 0)),
                },
            )
    elif isinstance(domains_raw, Mapping):
        for name, item in domains_raw.items():
            if not isinstance(item, Mapping):
                continue
            ip_val = item.get("ip", [])
            normalized.append(
                {
                    "name": _canonical_domain(str(name)),
                    "type": get_record_type(str(item.get("type", "A")).upper()),
                    "ip": list(ip_val) if isinstance(ip_val, list) else [str(ip_val)],
                    "registered": int(item.get("registered", 0)),
                },
            )
    return normalized


def sync_user_relations_from_dict(session: Session, user: User, doc: Mapping[str, Any]) -> None:  # noqa: C901, PLR0912, PLR0915
    if "domains" in doc:
        normalized_domains = _normalize_domain_list(doc.get("domains"))
        existing_by_key = {(d.name, d.type): d for d in (user.domains or [])}
        desired_keys: set[tuple[str, str]] = set()
        new_domains: list[Domain] = []
        for d_rec in normalized_domains:
            k = (d_rec["name"], d_rec["type"])
            if k in desired_keys:
                continue
            desired_keys.add(k)
            if k in existing_by_key:
                dom = existing_by_key[k]
                dom.ip = list(d_rec["ip"])
                dom.registered = int(d_rec["registered"])
                new_domains.append(dom)
            else:
                new_domains.append(
                    Domain(
                        user_id=user.id,
                        name=d_rec["name"],
                        type=d_rec["type"],
                        ip=list(d_rec["ip"]),
                        registered=int(d_rec["registered"]),
                    ),
                )
        user.domains = new_domains

    if "api_keys" in doc:
        raw_keys = doc.get("api_keys")
        if isinstance(raw_keys, Mapping):
            existing_keys = {k.id: k for k in (user.api_keys or [])}
            new_keys: list[ApiKey] = []
            for key_id, key_data in raw_keys.items():
                if not isinstance(key_data, Mapping):
                    continue
                if key_id in existing_keys:
                    ak = existing_keys[key_id]
                    ak.string = str(key_data.get("string", ""))
                    ak.perms = list(key_data.get("perms", []))
                    ak.domains = list(key_data.get("domains", []))
                    ak.comment = str(key_data.get("comment", ""))
                    new_keys.append(ak)
                else:
                    new_keys.append(
                        ApiKey(
                            id=str(key_id),
                            user_id=user.id,
                            string=str(key_data.get("string", "")),
                            perms=list(key_data.get("perms", [])),
                            domains=list(key_data.get("domains", [])),
                            comment=str(key_data.get("comment", "")),
                        ),
                    )
            user.api_keys = new_keys

    if "invites" in doc:
        raw_invites = doc.get("invites")
        if isinstance(raw_invites, Mapping):
            existing_invites = {inv.code: inv for inv in (user.invites or [])}
            new_invites: list[Invite] = []
            for code, inv_data in raw_invites.items():
                if not isinstance(inv_data, Mapping):
                    continue
                if code in existing_invites:
                    inv = existing_invites[code]
                    inv.used = bool(inv_data.get("used", False))
                    inv.used_by = inv_data.get("used_by")
                    inv.used_at = inv_data.get("used_at")
                    if inv_data.get("created") is not None:
                        inv.created = int(inv_data["created"])
                    new_invites.append(inv)
                else:
                    new_invites.append(
                        Invite(
                            code=str(code),
                            creator_id=user.id,
                            used=bool(inv_data.get("used", False)),
                            used_by=inv_data.get("used_by"),
                            used_at=inv_data.get("used_at"),
                            created=int(inv_data.get("created") or 0),
                        ),
                    )
            user.invites = new_invites

    if "tunnels" in doc:
        raw_tunnels = doc.get("tunnels")
        if isinstance(raw_tunnels, list):
            existing_tunnels = {t.id: t for t in (user.tunnels or [])}
            new_tunnels: list[ServeoTunnel] = []
            for t_data in raw_tunnels:
                if not isinstance(t_data, Mapping):
                    continue
                t_id = str(t_data.get("id") or t_data.get("_id") or "")
                if not t_id:
                    continue
                if t_id in existing_tunnels:
                    tun = existing_tunnels[t_id]
                    tun.serveo_auth_record = str(t_data.get("serveo_auth_record", ""))
                    tun.ssh_fingerprint = str(t_data.get("ssh_fingerprint", ""))
                    tun.subdomain = str(t_data.get("subdomain", ""))
                    tun.hostname = str(t_data.get("hostname", ""))
                    tun.service = str(t_data.get("service", ""))
                    tun.local_port = int(t_data.get("local_port", 80))
                    tun.command = str(t_data.get("command", ""))
                    tun.created_at = int(t_data.get("created_at", 0))
                    tun.updated_at = int(t_data.get("updated_at", 0))
                    new_tunnels.append(tun)
                else:
                    new_tunnels.append(
                        ServeoTunnel(
                            id=t_id,
                            user_id=user.id,
                            serveo_auth_record=str(t_data.get("serveo_auth_record", "")),
                            ssh_fingerprint=str(t_data.get("ssh_fingerprint", "")),
                            subdomain=str(t_data.get("subdomain", "")),
                            hostname=str(t_data.get("hostname", "")),
                            service=str(t_data.get("service", "")),
                            local_port=int(t_data.get("local_port", 80)),
                            command=str(t_data.get("command", "")),
                            created_at=int(t_data.get("created_at", 0)),
                            updated_at=int(t_data.get("updated_at", 0)),
                        ),
                    )
            user.tunnels = new_tunnels

    if "permissions" in doc and isinstance(doc.get("permissions"), Mapping):
        perms_row = user.permissions_rel or UserPermissions(user_id=user.id)
        perms_row.apply_dict(doc["permissions"])
        user.permissions_rel = perms_row
    elif user.permissions_rel is None:
        user.permissions_rel = UserPermissions(user_id=user.id)

    if "totp" in doc:
        raw_totp = doc.get("totp")
        if isinstance(raw_totp, Mapping) and (raw_totp.get("key") or raw_totp.get("verified")):
            mfa_row = user.mfa or UserMFA(user_id=user.id)
            mfa_row.verified = bool(raw_totp.get("verified", False))
            mfa_row.secret_key = str(raw_totp.get("key") or "")
            raw_rec = raw_totp.get("recovery")
            mfa_row.recovery_codes = list(raw_rec) if isinstance(raw_rec, list) else []
            flag_modified(mfa_row, "recovery_codes")
            user.mfa = mfa_row
        else:
            user.mfa = None

    if "accessed_from" in doc:
        raw_ips = doc.get("accessed_from")
        if isinstance(raw_ips, (list, tuple, set)):
            existing_ips = {row.ip: row for row in (user.ips or [])}
            seen_ips: set[str] = set()
            new_ips: list[UserIP] = []
            for idx, ip_val in enumerate(raw_ips):
                ip_str = str(ip_val).strip()
                if not ip_str or ip_str in seen_ips:
                    continue
                seen_ips.add(ip_str)
                if ip_str in existing_ips:
                    new_ips.append(existing_ips[ip_str])
                else:
                    new_ips.append(
                        UserIP(
                            user_id=user.id,
                            ip=ip_str,
                            first_seen=idx,
                            last_seen=idx,
                        ),
                    )
            user.ips = new_ips

    if "owned_tlds" in doc:
        raw_tlds = doc.get("owned_tlds")
        if isinstance(raw_tlds, (list, tuple, set)):
            existing_tlds = {row.tld: row for row in (user.owned_tlds_rel or [])}
            seen_tlds: set[str] = set()
            new_tlds: list[UserOwnedTLD] = []
            for tld_val in raw_tlds:
                tld_str = str(tld_val).strip()
                if not tld_str or tld_str in seen_tlds:
                    continue
                seen_tlds.add(tld_str)
                if tld_str in existing_tlds:
                    new_tlds.append(existing_tlds[tld_str])
                else:
                    new_tlds.append(UserOwnedTLD(user_id=user.id, tld=tld_str))
            user.owned_tlds_rel = new_tlds
    elif not user.owned_tlds_rel:
        user.owned_tlds_rel = [UserOwnedTLD(user_id=user.id, tld="eepy.page")]

    if "risk" in doc and isinstance(doc.get("risk"), Mapping):
        raw_risk = doc["risk"]
        rp = user.risk_profile or UserRiskProfile(user_id=user.id)
        rp.score = int(raw_risk.get("score") or 0)
        rp.locked = bool(raw_risk.get("locked", False))
        rp.disabled = bool(raw_risk.get("disabled", False))
        raw_reasons = raw_risk.get("disable_reasons")
        rp.disable_reasons = list(raw_reasons) if isinstance(raw_reasons, list) else []
        flag_modified(rp, "disable_reasons")
        user.risk_profile = rp

        raw_device_id = raw_risk.get("device_id")
        if isinstance(raw_device_id, str) and raw_device_id.strip():
            clean_dev = raw_device_id.strip()
            existing_devs = {d.device_id: d for d in (user.devices or [])}
            now_ts = int(datetime.now(UTC).timestamp())
            if clean_dev in existing_devs:
                existing_devs[clean_dev].last_seen = now_ts
            else:
                user.devices.append(
                    UserDevice(
                        user_id=user.id,
                        device_id=clean_dev,
                        first_seen=now_ts,
                        last_seen=now_ts,
                    ),
                )

        raw_flags = raw_risk.get("flags")
        if isinstance(raw_flags, Mapping):
            new_links: list[AltLink] = []
            for signal_type, flag_data in raw_flags.items():
                if not isinstance(flag_data, Mapping):
                    continue
                related_uid_raw = flag_data.get("user_id")
                related_uid = str(related_uid_raw) if related_uid_raw else None
                if related_uid is not None and session.get(User, related_uid) is None:
                    continue
                exp_val = flag_data.get("expires_at")
                new_links.append(
                    AltLink(
                        user_id=user.id,
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
    elif user.risk_profile is None:
        user.risk_profile = UserRiskProfile(user_id=user.id)

    session.add(user)


def populate_user_fields_from_dict(user: User, doc: Mapping[str, Any]) -> None:
    relational_keys = {
        "domains",
        "api_keys",
        "invites",
        "tunnels",
        "permissions",
        "totp",
        "accessed_from",
        "owned_tlds",
        "risk",
    }
    extra = dict(user.extra_data or {})

    for raw_key, value in doc.items():
        if raw_key in relational_keys:
            continue
        attr = USER_FIELD_MAP.get(raw_key)
        if attr is not None:
            if attr in {"created", "last_login", "credits", "beta_updated", "referred_count", "migration_version"}:
                setattr(user, attr, int(value) if value is not None else 0)
            elif attr in {"country", "feature_flags"}:
                setattr(user, attr, deepcopy(dict(value)) if isinstance(value, Mapping) else {})
                flag_modified(user, attr)
            elif attr == "ban_reasons":
                setattr(user, attr, list(value) if isinstance(value, (list, tuple, set)) else [])
                flag_modified(user, attr)
            else:
                setattr(user, attr, value)
        else:
            extra[raw_key] = deepcopy(value)

    user.extra_data = extra
    flag_modified(user, "extra_data")


def _set_dotted_key(doc: dict[str, Any], key: str, value: object) -> None:
    if "." not in key:
        doc[key] = value
        return
    parts = key.split(".")
    curr: Any = doc
    for part in parts[:-1]:
        if not isinstance(curr, dict):
            return
        if part not in curr or not isinstance(curr[part], dict):
            curr[part] = {}
        curr = curr[part]
    if isinstance(curr, dict):
        curr[parts[-1]] = value


class Table:
    def __init__(self, db_engine: "Engine | None", table_name: str) -> None:
        logger.info(f"Initializing table {table_name}")
        self.name: str = table_name
        self.engine: Engine
        if db_engine is None:
            self.engine = get_engine()
        elif hasattr(db_engine, "connect") and hasattr(db_engine, "dispose"):
            self.engine = db_engine  # pyright: ignore[reportAttributeAccessIssue]
        elif isinstance(db_engine, str):
            self.engine = create_db_engine(db_engine)
        else:
            self.engine = get_engine()

        self.model_cls: Any = TABLE_MODEL_MAP.get(table_name, User)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with session_scope(self.engine) as session:
            yield session

    def _model_from_dict(self, session: Session, document: Mapping[str, Any]) -> Any:  # noqa: ANN401, C901, PLR0911, PLR0912
        if self.model_cls is User:
            user_id = str(document.get("_id") or document.get("id") or "")
            user = session.get(User, user_id) if user_id else None
            if user is None:
                user = User(id=user_id)
            populate_user_fields_from_dict(user, document)
            sync_user_relations_from_dict(session, user, document)
            return user

        if self.model_cls is SessionModel:
            expires_val = document.get("expires") or document.get("expire") or datetime.now(UTC)
            if isinstance(expires_val, (int, float)):
                expires_val = datetime.fromtimestamp(expires_val, UTC)
            return SessionModel(
                id=str(document.get("_id") or document.get("id")),
                owner=str(document.get("owner", "")),
                owner_hash=document.get("owner_hash"),
                type=str(document.get("type", "access")),
                created=int(document.get("created", 0)),
                expires=expires_val,
                agent=str(document.get("agent", "")),
                ip=str(document.get("ip", "")),
                parent=document.get("parent"),
                manual_login=document.get("manual_login"),
            )

        if self.model_cls is VerificationCode:
            exp_after = document.get("expires_after") or datetime.now(UTC)
            return VerificationCode(
                id=str(document.get("_id") or document.get("id")),
                type=str(document.get("type", "")),
                account=str(document.get("account", "")),
                expire=int(document.get("expire", 0)),
                expires_after=exp_after,
            )

        if self.model_cls is Reward:
            return Reward(
                id=str(document.get("_id") or document.get("id")),
                created=int(document.get("created", 0)),
                mappings=dict(document.get("mappings", {})),
                associated_email=str(document.get("associated_email") or ""),
                email_hash=str(document.get("email_hash") or ""),
                used=bool(document.get("used", False)),
                used_by=document.get("used_by"),
            )

        if self.model_cls is Referral:
            ref_id = str(document.get("_id") or document.get("id"))
            ref = Referral(
                id=ref_id,
                owner=str(document.get("owner", "")),
                created=int(document.get("created", 0)),
            )
            raw_users = document.get("users")
            if isinstance(raw_users, list):
                for uid in raw_users:
                    uid_str = str(uid)
                    if session.get(User, uid_str) is not None:
                        ref.redemptions.append(
                            ReferralRedemption(
                                referral_id=ref_id,
                                referred_user_id=uid_str,
                                created_at=int(document.get("created", 0)),
                            ),
                        )
            return ref

        if self.model_cls is StatusModel:
            return StatusModel(
                id=str(document.get("_id") or document.get("id")),
                time=float(document.get("time", 0.0)),
                message=str(document.get("message", "")),
                active=bool(document.get("active", True)),
            )

        if self.model_cls is IPActivityModel:
            exp_after = document.get("expires_after") or datetime.now(UTC)
            return IPActivityModel(
                id=str(document.get("_id") or document.get("id") or f"{document.get('ip')}_{document.get('user_id')}"),
                ip=str(document.get("ip", "")),
                user_id=str(document.get("user_id", "")),
                last_seen=int(document.get("last_seen", 0)),
                expires_after=exp_after,
            )

        if self.model_cls is RecentLogoutModel:
            exp_after = document.get("expires_after") or datetime.now(UTC)
            return RecentLogoutModel(
                user_id=str(document.get("user_id", "")),
                ip=document.get("ip"),
                device_id=document.get("device_id"),
                time=int(document.get("time", 0)),
                expires_after=exp_after,
            )

        return self.model_cls(**document)

    def _build_where_clauses(self, where: Mapping[str, Any]) -> list[Any]:
        clauses: list[Any] = []
        for col_name, value in where.items():
            attr = getattr(self.model_cls, col_name, None)
            if attr is None:
                msg = f"Unknown column '{col_name}' on table '{self.name}'"
                raise ValueError(msg)
            clauses.append(attr == value)
        return clauses

    def get_by_id(self, record_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.get(self.model_cls, record_id)
            return row.to_dict() if row is not None else None

    def find_one(self, **where: object) -> dict[str, Any] | None:
        with self.session() as session:
            stmt = select(self.model_cls)
            for clause in self._build_where_clauses(where):
                stmt = stmt.where(clause)
            row = session.exec(stmt).first()
            return row.to_dict() if row is not None else None

    def find_all(self, **where: object) -> list[dict[str, Any]]:
        with self.session() as session:
            stmt = select(self.model_cls)
            for clause in self._build_where_clauses(where):
                stmt = stmt.where(clause)
            rows = session.exec(stmt).all()
            return [row.to_dict() for row in rows]

    def get_table(self) -> list[dict[str, Any]]:
        return self.find_all()

    def insert_document(self, document: Mapping[Any, Any]) -> None:
        with self.session() as session:
            model_obj = self._model_from_dict(session, document)
            session.add(model_obj)

    def set_field(
        self,
        record_id: str,
        key: str,
        value: Any,  # noqa: ANN401
        *,
        ignore_no_matches: bool = False,
    ) -> None:
        with self.session() as session:
            target = session.get(self.model_cls, record_id)
            if target is None:
                if not ignore_no_matches:
                    logger.error(f"Record '{record_id}' not found on table {self.name}")
                    msg = f"Record '{record_id}' not found"
                    raise FilterMatchError(msg)
                return

            doc = target.to_dict()
            _set_dotted_key(doc, key, deepcopy(value))
            if isinstance(target, User):
                populate_user_fields_from_dict(target, doc)
                sync_user_relations_from_dict(session, target, doc)
            else:
                updated = self._model_from_dict(session, doc)
                session.merge(updated)

    def delete_by_id(self, record_id: str) -> bool:
        logger.info(f"Deleting record '{record_id}' on table {self.name}")
        with self.session() as session:
            row = session.get(self.model_cls, record_id)
            if row is None:
                return False
            session.delete(row)
            return True

    def delete_where(self, **where: object) -> int:
        logger.info(f"Deleting records matching {where} on table {self.name}")
        with self.session() as session:
            stmt = delete(self.model_cls)
            for clause in self._build_where_clauses(where):
                stmt = stmt.where(clause)
            result = session.exec(stmt)
            return int(result.rowcount or 0)  # pyright: ignore[reportAttributeAccessIssue]
