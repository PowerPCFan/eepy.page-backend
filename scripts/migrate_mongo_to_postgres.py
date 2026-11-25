#!/usr/bin/env python3
"""One-time migration script from MongoDB to PostgreSQL (SQLModel).

Guarantees:
1. Strictly READ-ONLY on MongoDB: never inserts, updates, deletes, or creates indexes on Mongo.
2. Thoroughly normalizes all legacy MongoDB document structures in-memory before writing to PostgreSQL:
   - Converts embedded domains (legacy dict or list), API keys, invites, and Serveo tunnels into relational tables.
   - Normalizes hyphenated keys (including nested permission/limit keys and reward mappings) to snake_case.
   - Backfills email_hash, normalized_email_hash, owned_tlds, risk, and lowercase username hashes.
   - Cleans up legacy ip_activity and recent_logouts records.
3. Idempotent on PostgreSQL (uses session.merge) and supports --dry-run.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

scripts_dir = pathlib.Path(__file__).resolve().parent
backend_dir = scripts_dir.parent
sys.path.insert(0, str(backend_dir / "src"))
sys.path.insert(0, str(scripts_dir))

from simple_python_dotenv import load_dotenv  # noqa: E402

load_dotenv(backend_dir / ".env")

if TYPE_CHECKING:
    from src.database.session import create_db_engine, session_scope
    from src.database.tables.domains import Domains
    from src.database.tables.ip_activity import (
        IP_ACTIVITY_TTL_SECONDS,
        LOGOUT_VELOCITY_WINDOW_SECONDS,
        expiry_from_epoch,
    )
    from src.database.tables.users import USER_MIGRATION_VERSION
    from src.mail.email import normalize_email_address
    from src.database.models import (
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
    from src.security.encryption import Encryption
    from src.security.risk import create_default_risk, normalize_device_id
else:
    from database.session import create_db_engine, session_scope
    from database.tables.domains import Domains
    from database.tables.ip_activity import (
        IP_ACTIVITY_TTL_SECONDS,
        LOGOUT_VELOCITY_WINDOW_SECONDS,
        expiry_from_epoch,
    )
    from database.tables.users import USER_MIGRATION_VERSION
    from mail.email import normalize_email_address
    from database.models import (
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
    from security.encryption import Encryption
    from security.risk import create_default_risk, normalize_device_id


@dataclass
class MigrationSummary:
    users: int = 0
    domains: int = 0
    api_keys: int = 0
    invites: int = 0
    tunnels: int = 0
    user_ips: int = 0
    user_devices: int = 0
    alt_links: int = 0
    sessions: int = 0
    codes: int = 0
    rewards: int = 0
    referrals: int = 0
    referral_redemptions: int = 0
    statuses: int = 0
    ip_activities: int = 0
    recent_logouts: int = 0
    skipped_legacy_ip_activity: int = 0
    skipped_legacy_logouts: int = 0
    username_collisions: int = 0


@dataclass
class TransformedUserBundle:
    user: User
    permissions: UserPermissions
    mfa: UserMFA | None
    ips: list[UserIP]
    owned_tlds: list[UserOwnedTLD]
    risk_profile: UserRiskProfile
    devices: list[UserDevice]
    alt_links: list[AltLink]
    domains: list[Domain]
    api_keys: list[ApiKey]
    invites: list[Invite]
    tunnels: list[ServeoTunnel]


KNOWN_USER_KEYS = {
    "_id",
    "id",
    "email",
    "email-hash",
    "email_hash",
    "normalized-email-hash",
    "normalized_email_hash",
    "password",
    "display-name",
    "display_name",
    "username",
    "lang",
    "country",
    "accessed-from",
    "accessed_from",
    "created",
    "last-login",
    "last_login",
    "permissions",
    "feature-flags",
    "feature_flags",
    "verified",
    "domains",
    "tunnels",
    "api-keys",
    "api_keys",
    "credits",
    "beta-enroll",
    "beta_enroll",
    "beta-updated",
    "beta_updated",
    "invites",
    "invite-code",
    "invite_code",
    "totp",
    "banned",
    "ban-reasons",
    "ban_reasons",
    "unbanned",
    "deleted-in",
    "deleted_in",
    "referral-code",
    "referral_code",
    "referred-by",
    "referred_by",
    "referred-count",
    "referred_count",
    "owned-tlds",
    "owned_tlds",
    "risk",
    "migration-version",
    "migration_version",
}


def normalize_permissions(raw_perms: object) -> dict[str, Any]:
    if not isinstance(raw_perms, Mapping):
        return {
            "admin": {"enabled": False, "permissions": {}},
            "limits": {"max_domains": 3, "max_subdomains": 5},
            "features": {"invite": False},
        }
    perms = deepcopy(dict(raw_perms))
    admin = perms.get("admin")
    if isinstance(admin, Mapping):
        admin_dict = dict(admin)
        inner_perms = admin_dict.get("permissions")
        if isinstance(inner_perms, Mapping):
            new_inner = {}
            for k, v in inner_perms.items():
                norm_k = "manage_permissions" if k == "manage-permissions" else k.replace("-", "_")
                new_inner[norm_k] = v
            admin_dict["permissions"] = new_inner
        perms["admin"] = admin_dict

    limits = perms.get("limits")
    if isinstance(limits, Mapping):
        limits_dict = dict(limits)
        if "max-domains" in limits_dict:
            limits_dict["max_domains"] = limits_dict.pop("max-domains")
        if "max-subdomains" in limits_dict:
            limits_dict["max_subdomains"] = limits_dict.pop("max-subdomains")
        limits_dict.setdefault("max_domains", 3)
        limits_dict.setdefault("max_subdomains", 5)
        perms["limits"] = limits_dict

    return perms


def normalize_reward_mappings(raw_mappings: object) -> dict[str, Any]:
    if not isinstance(raw_mappings, Mapping):
        return {}
    result: dict[str, Any] = {}
    for op, fields in raw_mappings.items():
        if not isinstance(fields, Mapping):
            result[op] = deepcopy(fields)
            continue
        new_fields: dict[str, Any] = {}
        for k, v in fields.items():
            norm_k = (
                k.replace("owned-tlds", "owned_tlds")
                .replace("max-domains", "max_domains")
                .replace("max-subdomains", "max_subdomains")
                .replace("manage-permissions", "manage_permissions")
                .replace("referred-count", "referred_count")
            )
            if op == "$addToSet" and norm_k == "owned_tlds":
                tlds = v["$each"] if (isinstance(v, Mapping) and "$each" in v) else [v]
                grant_tlds = result.setdefault("grant_tlds", [])
                for tld in tlds:
                    if isinstance(tld, str) and tld not in grant_tlds:
                        grant_tlds.append(tld)
                continue
            new_fields[norm_k] = deepcopy(v)
        if new_fields:
            result[op] = new_fields
    return result


def detect_username_collisions(raw_users: list[dict[str, Any]], encryption: Encryption) -> set[str]:
    by_lower_hash: dict[str, list[str]] = {}
    for doc in raw_users:
        user_id = str(doc.get("_id") or doc.get("id") or "")
        if not user_id:
            continue
        lower_hash = doc.get("username")
        display_enc = doc.get("display-name") or doc.get("display_name")
        if not lower_hash and isinstance(display_enc, str) and display_enc:
            try:
                decrypted = encryption.decrypt(display_enc).strip()
                if decrypted:
                    lower_hash = Encryption.sha256(decrypted.lower())
            except Exception:  # noqa: S112
                continue
        if isinstance(lower_hash, str) and lower_hash:
            by_lower_hash.setdefault(lower_hash, []).append(user_id)

    colliding_hashes: set[str] = {h for h, ids in by_lower_hash.items() if len(ids) > 1}
    return colliding_hashes


def transform_user(  # noqa: C901, PLR0912, PLR0915
    doc: Mapping[str, Any],
    encryption: Encryption,
    colliding_username_hashes: set[str],
    valid_user_ids: set[str],
    summary: MigrationSummary,
) -> TransformedUserBundle:
    user_id = str(doc.get("_id") or doc.get("id"))
    email_enc = str(doc.get("email") or "")
    email_hash = doc.get("email-hash") or doc.get("email_hash")
    norm_email_hash = doc.get("normalized-email-hash") or doc.get("normalized_email_hash")

    if email_enc:
        try:
            raw_email = encryption.decrypt(email_enc).strip()
            if raw_email:
                normalized = normalize_email_address(raw_email)
                norm_email_hash = encryption.hash_email(normalized)
                email_hash = encryption.hash_email(raw_email)
        except Exception:  # noqa: S110
            pass

    display_name = str(doc.get("display-name") or doc.get("display_name") or "")
    username = doc.get("username")
    if not username and display_name:
        try:
            decrypted_name = encryption.decrypt(display_name).strip()
            if decrypted_name:
                candidate_hash = Encryption.sha256(decrypted_name.lower())
                if candidate_hash in colliding_username_hashes:
                    summary.username_collisions += 1
                else:
                    username = candidate_hash
        except Exception:  # noqa: S110
            pass

    accessed_raw = doc.get("accessed-from") if "accessed-from" in doc else doc.get("accessed_from", [])
    accessed_from = (
        list(dict.fromkeys(str(ip).strip() for ip in accessed_raw if str(ip).strip()))
        if isinstance(accessed_raw, list)
        else []
    )

    owned_tlds_raw = doc.get("owned-tlds") if "owned-tlds" in doc else doc.get("owned_tlds")
    owned_tlds = (
        list(dict.fromkeys(str(t).strip() for t in owned_tlds_raw if str(t).strip()))
        if isinstance(owned_tlds_raw, list)
        else ["eepy.page"]
    )

    permissions = normalize_permissions(doc.get("permissions"))
    is_admin = bool(permissions.get("admin", {}).get("enabled", False))

    risk_raw = doc.get("risk")
    risk: dict[str, Any]
    if isinstance(risk_raw, Mapping) and risk_raw:
        risk = dict(risk_raw)
    else:
        risk = dict(create_default_risk(is_admin=is_admin))

    feature_flags_raw = doc.get("feature-flags") if "feature-flags" in doc else doc.get("feature_flags", {})
    if isinstance(feature_flags_raw, Mapping):
        feature_flags = {str(k).replace("-", "_"): bool(v) for k, v in feature_flags_raw.items()}
    else:
        feature_flags = {}

    ban_reasons_raw = doc.get("ban-reasons") if "ban-reasons" in doc else doc.get("ban_reasons", [])
    ban_reasons = [str(r) for r in ban_reasons_raw] if isinstance(ban_reasons_raw, list) else []

    deleted_in = doc.get("deleted-in") or doc.get("deleted_in")
    if isinstance(deleted_in, datetime) and deleted_in.tzinfo is None:
        deleted_in = deleted_in.replace(tzinfo=UTC)
    elif not isinstance(deleted_in, datetime):
        deleted_in = None

    extra_data: dict[str, Any] = {
        str(k).replace("-", "_"): deepcopy(v) for k, v in doc.items() if k not in KNOWN_USER_KEYS
    }

    created_ts = int(doc.get("created") or 0)
    last_login_ts = int(doc.get("last-login") or doc.get("last_login") or 0)

    user_model = User(
        id=user_id,
        email=email_enc,
        email_hash=str(email_hash) if email_hash else None,
        normalized_email_hash=str(norm_email_hash) if norm_email_hash else None,
        password=doc.get("password"),
        display_name=display_name,
        username=str(username) if username else None,
        lang=str(doc.get("lang") or "en"),
        country=dict(doc.get("country") or {}) if isinstance(doc.get("country"), Mapping) else {},
        created=created_ts,
        last_login=last_login_ts,
        feature_flags=feature_flags,
        verified=bool(doc.get("verified", False)),
        credits=int(doc.get("credits", 200)),
        beta_enroll=bool(doc.get("beta-enroll") or doc.get("beta_enroll") or False),
        beta_updated=int(doc.get("beta-updated") or doc.get("beta_updated") or 0),
        invite_code=str(doc.get("invite-code") or doc.get("invite_code") or ""),
        banned=bool(doc.get("banned", False)),
        ban_reasons=ban_reasons,
        unbanned=int(doc["unbanned"]) if doc.get("unbanned") is not None else None,
        deleted_in=deleted_in,
        referral_code=str(doc.get("referral-code") or doc.get("referral_code") or ""),
        referred_by=str(doc.get("referred-by") or doc.get("referred_by") or ""),
        referred_count=int(doc.get("referred-count") or doc.get("referred_count") or 0),
        migration_version=USER_MIGRATION_VERSION,
        extra_data=extra_data,
    )

    limits = permissions.get("limits") if isinstance(permissions, Mapping) else None
    features = permissions.get("features") if isinstance(permissions, Mapping) else None
    admin_cfg = permissions.get("admin") if isinstance(permissions, Mapping) else None
    admin_perms = admin_cfg.get("permissions") if isinstance(admin_cfg, Mapping) else None
    perms_model = UserPermissions(
        user_id=user_id,
        max_domains=int(limits["max_domains"])
        if isinstance(limits, Mapping) and limits.get("max_domains") is not None
        else 3,
        max_subdomains=(
            int(limits["max_subdomains"])
            if isinstance(limits, Mapping) and limits.get("max_subdomains") is not None
            else 5
        ),
        feature_invite=bool(features.get("invite", False)) if isinstance(features, Mapping) else False,
        admin_enabled=bool(admin_cfg.get("enabled", False)) if isinstance(admin_cfg, Mapping) else False,
        admin_account=bool(admin_perms.get("account", False)) if isinstance(admin_perms, Mapping) else False,
        admin_dns=bool(admin_perms.get("dns", False)) if isinstance(admin_perms, Mapping) else False,
        admin_manage_permissions=(
            bool(admin_perms.get("manage_permissions", False)) if isinstance(admin_perms, Mapping) else False
        ),
        admin_reports=bool(admin_perms.get("reports", False)) if isinstance(admin_perms, Mapping) else False,
        admin_userdetails=bool(admin_perms.get("userdetails", False)) if isinstance(admin_perms, Mapping) else False,
        admin_wildcards=bool(admin_perms.get("wildcards", False)) if isinstance(admin_perms, Mapping) else False,
    )

    # Normalized MFA
    raw_totp = doc.get("totp")
    mfa_model: UserMFA | None = None
    if isinstance(raw_totp, Mapping) and (raw_totp.get("key") or raw_totp.get("verified")):
        raw_rec = raw_totp.get("recovery")
        mfa_model = UserMFA(
            user_id=user_id,
            verified=bool(raw_totp.get("verified", False)),
            secret_key=str(raw_totp.get("key") or ""),
            recovery_codes=[str(c) for c in raw_rec] if isinstance(raw_rec, list) else [],
        )

    # Normalized User IPs
    ip_models = [
        UserIP(
            user_id=user_id,
            ip=ip_val,
            first_seen=created_ts or idx,
            last_seen=last_login_ts or idx,
        )
        for idx, ip_val in enumerate(accessed_from)
    ]

    # Normalized Owned TLDs
    owned_tld_models = [UserOwnedTLD(user_id=user_id, tld=tld) for tld in owned_tlds]

    # Normalized Risk Profile, Devices, and Alt Links
    raw_disable_reasons = risk.get("disable_reasons")
    risk_profile_model = UserRiskProfile(
        user_id=user_id,
        score=int(risk.get("score") or 0),
        locked=bool(risk.get("locked", False)),
        disabled=bool(risk.get("disabled", False)),
        disable_reasons=[str(r) for r in raw_disable_reasons] if isinstance(raw_disable_reasons, list) else [],
    )

    device_models: list[UserDevice] = []
    clean_dev = normalize_device_id(risk.get("device_id"))
    if clean_dev:
        device_models.append(
            UserDevice(
                user_id=user_id,
                device_id=clean_dev,
                first_seen=created_ts,
                last_seen=last_login_ts or created_ts,
            ),
        )

    alt_link_models: list[AltLink] = []
    raw_flags = risk.get("flags")
    if isinstance(raw_flags, Mapping):
        for signal_type, flag_data in raw_flags.items():
            if not isinstance(flag_data, Mapping):
                continue
            rel_uid_raw = flag_data.get("user_id")
            rel_uid = str(rel_uid_raw) if rel_uid_raw else None
            if rel_uid is not None and rel_uid not in valid_user_ids:
                continue
            exp_val = flag_data.get("expires_at")
            alt_link_models.append(
                AltLink(
                    user_id=user_id,
                    related_user_id=rel_uid,
                    signal_type=str(signal_type),
                    score=int(flag_data.get("score") or 0),
                    reason=str(flag_data.get("reason") or ""),
                    detected_at=int(flag_data.get("detected_at") or 0),
                    expires_at=int(exp_val) if exp_val is not None else None,
                    permanent=bool(flag_data.get("permanent", False)),
                ),
            )

    # Normalized domains
    raw_domains = doc.get("domains")
    raw_domain_entries: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(raw_domains, list):
        for item in raw_domains:
            if isinstance(item, Mapping) and item.get("name"):
                raw_domain_entries.append((str(item["name"]), item))
    elif isinstance(raw_domains, Mapping):
        for dom_name, item in raw_domains.items():
            if isinstance(item, Mapping):
                raw_domain_entries.append((str(dom_name), item))

    seen_domain_keys: set[tuple[str, str]] = set()
    domain_models: list[Domain] = []
    for dom_name, item in raw_domain_entries:
        canonical_name = Domains.canonical_full_domain_name(dom_name)
        record_type = str(item.get("type", "A")).upper()
        key = (canonical_name, record_type)
        if key in seen_domain_keys:
            continue
        seen_domain_keys.add(key)
        raw_ip = item.get("ip", [])
        domain_models.append(
            Domain(
                user_id=user_id,
                name=canonical_name,
                type=record_type,
                ip=list(raw_ip) if isinstance(raw_ip, list) else [str(raw_ip)],
                registered=int(item.get("registered", 0)),
            ),
        )

    # Normalized API keys
    raw_api_keys = doc.get("api-keys") if "api-keys" in doc else doc.get("api_keys", {})
    api_key_models: list[ApiKey] = []
    if isinstance(raw_api_keys, Mapping):
        for key_hash, key_data in raw_api_keys.items():
            if not isinstance(key_data, Mapping):
                continue
            raw_key_domains = key_data.get("domains", [])
            norm_key_domains = [
                d if d == "*" else Domains.canonical_full_domain_name(str(d))
                for d in (raw_key_domains if isinstance(raw_key_domains, list) else [])
            ]
            api_key_models.append(
                ApiKey(
                    id=str(key_hash),
                    user_id=user_id,
                    string=str(key_data.get("string") or ""),
                    perms=[str(p) for p in key_data.get("perms", [])],
                    domains=norm_key_domains,
                    comment=str(key_data.get("comment") or ""),
                ),
            )

    # Invites
    raw_invites = doc.get("invites", {})
    invite_models: list[Invite] = []
    if isinstance(raw_invites, Mapping):
        for code, inv_data in raw_invites.items():
            if not isinstance(inv_data, Mapping):
                continue
            invite_models.append(
                Invite(
                    code=str(code),
                    creator_id=user_id,
                    used=bool(inv_data.get("used", False)),
                    used_by=inv_data.get("used_by"),
                    used_at=int(inv_data["used_at"]) if inv_data.get("used_at") is not None else None,
                    created=int(inv_data.get("created") or 0),
                ),
            )

    # Serveo tunnels
    raw_tunnels = doc.get("tunnels", [])
    tunnel_models: list[ServeoTunnel] = []
    if isinstance(raw_tunnels, list):
        for t_data in raw_tunnels:
            if not isinstance(t_data, Mapping):
                continue
            t_id = str(t_data.get("id") or t_data.get("_id") or "")
            if not t_id:
                continue
            tunnel_models.append(
                ServeoTunnel(
                    id=t_id,
                    user_id=user_id,
                    serveo_auth_record=str(t_data.get("serveo_auth_record") or ""),
                    ssh_fingerprint=str(t_data.get("ssh_fingerprint") or ""),
                    subdomain=str(t_data.get("subdomain") or ""),
                    hostname=str(t_data.get("hostname") or ""),
                    service=str(t_data.get("service") or ""),
                    local_port=int(t_data.get("local_port") or 80),
                    command=str(t_data.get("command") or ""),
                    created_at=int(t_data.get("created_at") or 0),
                    updated_at=int(t_data.get("updated_at") or 0),
                ),
            )

    return TransformedUserBundle(
        user=user_model,
        permissions=perms_model,
        mfa=mfa_model,
        ips=ip_models,
        owned_tlds=owned_tld_models,
        risk_profile=risk_profile_model,
        devices=device_models,
        alt_links=alt_link_models,
        domains=domain_models,
        api_keys=api_key_models,
        invites=invite_models,
        tunnels=tunnel_models,
    )


def run_migration(  # noqa: C901, PLR0912, PLR0915
    mongo_url: str,
    postgres_url: str,
    mongo_db_name: str = "database",
    *,
    dry_run: bool = False,
) -> MigrationSummary:
    try:
        from pymongo import MongoClient  # noqa: PLC0415
    except ImportError as exc:
        msg = "pymongo is required to run the Mongo-to-Postgres migration script (pip install pymongo)"
        raise RuntimeError(msg) from exc

    if not os.getenv("EMAIL_PEPPER"):
        msg = "EMAIL_PEPPER must be set in environment before running migration"
        raise RuntimeError(msg)

    summary = MigrationSummary()
    encryption = Encryption(os.getenv("ENC_KEY") or "none")

    # Connect to MongoDB strictly for reading
    with MongoClient(mongo_url) as mongo_client:
        db = mongo_client[mongo_db_name]

        # 1. Users + embedded relational models
        raw_users: list[dict[str, Any]] = list(db["eepy.page"].find({}))
        colliding_hashes = detect_username_collisions(raw_users, encryption)
        valid_user_ids = {str(doc.get("_id") or doc.get("id")) for doc in raw_users if doc.get("_id") or doc.get("id")}

        transformed_users: list[TransformedUserBundle] = []
        for raw_user in raw_users:
            bundle = transform_user(raw_user, encryption, colliding_hashes, valid_user_ids, summary)
            transformed_users.append(bundle)
            summary.users += 1
            summary.domains += len(bundle.domains)
            summary.api_keys += len(bundle.api_keys)
            summary.invites += len(bundle.invites)
            summary.tunnels += len(bundle.tunnels)
            summary.user_ips += len(bundle.ips)
            summary.user_devices += len(bundle.devices)
            summary.alt_links += len(bundle.alt_links)

        # 2. Sessions
        session_models: list[SessionModel] = []
        for s_doc in db["sessions"].find({}):
            s_id = str(s_doc.get("_id") or s_doc.get("id") or "")
            if not s_id:
                continue
            expires_val = s_doc.get("expires") or s_doc.get("expire") or datetime.now(UTC)
            if isinstance(expires_val, (int, float)):
                expires_val = datetime.fromtimestamp(expires_val, UTC)
            elif isinstance(expires_val, datetime) and expires_val.tzinfo is None:
                expires_val = expires_val.replace(tzinfo=UTC)

            manual_login = s_doc.get("manual-login") or s_doc.get("manual_login")
            if isinstance(manual_login, Mapping):
                ml_dict = dict(manual_login)
                if "user-id" in ml_dict:
                    ml_dict["user_id"] = ml_dict.pop("user-id")
                meta = ml_dict.get("metadata")
                if isinstance(meta, Mapping):
                    meta_dict = dict(meta)
                    if "accessed-from" in meta_dict:
                        meta_dict["accessed_from"] = meta_dict.pop("accessed-from")
                    if "last-login" in meta_dict:
                        meta_dict["last_login"] = meta_dict.pop("last-login")
                    ml_dict["metadata"] = meta_dict
                manual_login = ml_dict

            session_models.append(
                SessionModel(
                    id=s_id,
                    owner=str(s_doc.get("owner") or ""),
                    owner_hash=s_doc.get("owner-hash") or s_doc.get("owner_hash"),
                    type=str(s_doc.get("type") or "access"),
                    created=int(s_doc.get("created") or 0),
                    expires=expires_val,
                    agent=str(s_doc.get("agent") or ""),
                    ip=str(s_doc.get("ip") or ""),
                    parent=s_doc.get("parent"),
                    manual_login=manual_login if isinstance(manual_login, dict) else None,
                ),
            )
            summary.sessions += 1

        # 3. Verification / Recovery / Deletion Codes
        code_models: list[VerificationCode] = []
        for c_doc in db["codes"].find({}):
            c_id = str(c_doc.get("_id") or c_doc.get("id") or "")
            if not c_id:
                continue
            expire_ts = int(c_doc.get("expire") or 0)
            exp_after = c_doc.get("expiresAfter") or c_doc.get("expires_after")
            if not isinstance(exp_after, datetime):
                exp_after = datetime.fromtimestamp(expire_ts, UTC)
            elif exp_after.tzinfo is None:
                exp_after = exp_after.replace(tzinfo=UTC)

            code_models.append(
                VerificationCode(
                    id=c_id,
                    type=str(c_doc.get("type") or ""),
                    account=str(c_doc.get("account") or ""),
                    expire=expire_ts,
                    expires_after=exp_after,
                ),
            )
            summary.codes += 1

        # 4. Rewards
        reward_models: list[Reward] = []
        for r_doc in db["rewards"].find({}):
            r_id = str(r_doc.get("_id") or r_doc.get("id") or "")
            if not r_id:
                continue
            assoc_email_enc = str(r_doc.get("associated-email") or r_doc.get("associated_email") or "")
            reward_email_hash = str(r_doc.get("email-hash") or r_doc.get("email_hash") or "")
            if assoc_email_enc:
                try:
                    raw_reward_email = encryption.decrypt(assoc_email_enc).strip()
                    if raw_reward_email:
                        reward_email_hash = encryption.hash_email(raw_reward_email)
                except Exception:  # noqa: S110
                    pass
            reward_models.append(
                Reward(
                    id=r_id,
                    created=int(r_doc.get("created") or 0),
                    mappings=normalize_reward_mappings(r_doc.get("mappings")),
                    associated_email=assoc_email_enc,
                    email_hash=reward_email_hash,
                    used=bool(r_doc.get("used", False)),
                    used_by=r_doc.get("used-by") or r_doc.get("used_by"),
                ),
            )
            summary.rewards += 1

        # 5. Referrals & Redemptions
        referral_models: list[tuple[Referral, list[ReferralRedemption]]] = []
        for ref_doc in db["referrals"].find({}):
            ref_id = str(ref_doc.get("_id") or ref_doc.get("id") or "")
            owner_id = str(ref_doc.get("owner") or "")
            if not ref_id or owner_id not in valid_user_ids:
                continue
            created_ts = int(ref_doc.get("created") or 0)
            redemptions = [
                ReferralRedemption(
                    referral_id=ref_id,
                    referred_user_id=str(u),
                    created_at=created_ts,
                )
                for u in ref_doc.get("users", [])
                if isinstance(u, str) and u in valid_user_ids
            ]
            referral_models.append(
                (
                    Referral(
                        id=ref_id,
                        owner=owner_id,
                        created=created_ts,
                    ),
                    redemptions,
                ),
            )
            summary.referrals += 1
            summary.referral_redemptions += len(redemptions)

        # 6. Status
        status_models: list[StatusModel] = []
        for st_doc in db["status"].find({}):
            st_id = str(st_doc.get("_id") or st_doc.get("id") or "")
            if not st_id:
                continue
            status_models.append(
                StatusModel(
                    id=st_id,
                    time=float(st_doc.get("time") or 0.0),
                    message=str(st_doc.get("message") or ""),
                    active=bool(st_doc.get("active", False)),
                ),
            )
            summary.statuses += 1

        # 7. IP Activity (with legacy cleanup/backfill in-memory)
        now_epoch = round(datetime.now(UTC).timestamp())
        ip_activity_models: list[IPActivityModel] = []
        for ip_doc in db["ip_activity"].find({}):
            last_seen = ip_doc.get("last_seen")
            if not isinstance(last_seen, (int, float)):
                summary.skipped_legacy_ip_activity += 1
                continue
            exp_after = ip_doc.get("expiresAfter") or ip_doc.get("expires_after")
            if not isinstance(exp_after, datetime):
                if int(last_seen) <= now_epoch - IP_ACTIVITY_TTL_SECONDS:
                    summary.skipped_legacy_ip_activity += 1
                    continue
                exp_after = expiry_from_epoch(float(last_seen), IP_ACTIVITY_TTL_SECONDS)
            elif exp_after.tzinfo is None:
                exp_after = exp_after.replace(tzinfo=UTC)

            ip_val = str(ip_doc.get("ip") or "")
            uid_val = str(ip_doc.get("user_id") or "")
            doc_id = str(ip_doc.get("_id") or ip_doc.get("id") or f"{ip_val}_{uid_val}")
            ip_activity_models.append(
                IPActivityModel(
                    id=doc_id,
                    ip=ip_val,
                    user_id=uid_val,
                    last_seen=int(last_seen),
                    expires_after=exp_after,
                ),
            )
            summary.ip_activities += 1

        # 8. Recent Logouts
        logout_models: list[RecentLogoutModel] = []
        for l_doc in db["recent_logouts"].find({}):
            exp_after = l_doc.get("expiresAfter") or l_doc.get("expires_after")
            time_val = l_doc.get("time")
            if not isinstance(exp_after, datetime) or not isinstance(time_val, (int, float)):
                summary.skipped_legacy_logouts += 1
                continue
            if exp_after.tzinfo is None:
                exp_after = exp_after.replace(tzinfo=UTC)
            if int(time_val) < now_epoch - LOGOUT_VELOCITY_WINDOW_SECONDS:
                summary.skipped_legacy_logouts += 1
                continue
            logout_models.append(
                RecentLogoutModel(
                    user_id=str(l_doc.get("user_id") or ""),
                    ip=l_doc.get("ip"),
                    device_id=l_doc.get("device_id"),
                    time=int(time_val),
                    expires_after=exp_after,
                ),
            )
            summary.recent_logouts += 1

    if dry_run:
        return summary

    engine = create_db_engine(postgres_url, init_tables=True)

    # Persist everything to PostgreSQL within a transaction
    with session_scope(engine) as session:
        # Pass 1: persist all User rows and non-cross-user child records
        merged_users: list[tuple[User, TransformedUserBundle]] = []
        for bundle in transformed_users:
            merged_user = session.merge(bundle.user)
            session.flush()
            merged_user.permissions_rel = bundle.permissions
            merged_user.mfa = bundle.mfa
            merged_user.ips = bundle.ips
            merged_user.owned_tlds_rel = bundle.owned_tlds
            merged_user.risk_profile = bundle.risk_profile
            merged_user.devices = bundle.devices
            merged_user.domains = bundle.domains
            merged_user.api_keys = bundle.api_keys
            merged_user.invites = bundle.invites
            merged_user.tunnels = bundle.tunnels
            session.add(merged_user)
            merged_users.append((merged_user, bundle))

        session.flush()

        # Pass 2: persist cross-user alt_links now that all User rows exist
        for merged_user, bundle in merged_users:
            merged_user.alt_links = bundle.alt_links
            session.add(merged_user)

        for s_model in session_models:
            session.merge(s_model)

        for c_model in code_models:
            session.merge(c_model)

        for r_model in reward_models:
            session.merge(r_model)

        for ref_model, redemptions in referral_models:
            merged_ref = session.merge(ref_model)
            session.flush()
            merged_ref.redemptions = redemptions
            session.add(merged_ref)

        for st_model in status_models:
            session.merge(st_model)

        for ip_model in ip_activity_models:
            session.merge(ip_model)

        for l_model in logout_models:
            session.add(l_model)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate eepy.page data from MongoDB to PostgreSQL (read-only on Mongo)",
    )
    parser.add_argument("--mongo-url", default=os.getenv("MONGODB_URL", ""), help="MongoDB connection URI")
    parser.add_argument("--postgres-url", default=os.getenv("POSTGRES_URL", ""), help="PostgreSQL connection URI")
    parser.add_argument("--mongo-db", default="database", help="MongoDB database name (default: 'database')")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and transform all Mongo data without writing to Postgres",
    )
    args = parser.parse_args()

    if not args.mongo_url:
        print("Error: MONGODB_URL or --mongo-url must be provided", file=sys.stderr)
        return 2
    if not args.postgres_url and not args.dry_run:
        print("Error: POSTGRES_URL or --postgres-url must be provided", file=sys.stderr)
        return 2

    mode_str = "DRY RUN (no database writes)" if args.dry_run else "LIVE MIGRATION (read-only on MongoDB)"
    print(f"Starting Mongo -> PostgreSQL migration [{mode_str}]...")

    summary = run_migration(
        mongo_url=args.mongo_url,
        postgres_url=args.postgres_url,
        mongo_db_name=args.mongo_db,
        dry_run=args.dry_run,
    )

    print("\nMigration Summary:")
    print(f"  Users migrated:              {summary.users}")
    print(f"  Domains migrated:            {summary.domains}")
    print(f"  API keys migrated:           {summary.api_keys}")
    print(f"  Invites migrated:            {summary.invites}")
    print(f"  Serveo tunnels migrated:     {summary.tunnels}")
    print(f"  User IPs migrated:           {summary.user_ips}")
    print(f"  User devices migrated:       {summary.user_devices}")
    print(f"  Alt links migrated:          {summary.alt_links}")
    print(f"  Sessions migrated:           {summary.sessions}")
    print(f"  Codes migrated:              {summary.codes}")
    print(f"  Rewards migrated:            {summary.rewards}")
    print(f"  Referrals migrated:          {summary.referrals} ({summary.referral_redemptions} redemptions)")
    print(f"  Status records migrated:     {summary.statuses}")
    print(
        f"  IP activity rows migrated:   {summary.ip_activities} "
        f"(skipped {summary.skipped_legacy_ip_activity} expired/corrupt)",
    )
    print(
        f"  Recent logouts migrated:     {summary.recent_logouts} "
        f"(skipped {summary.skipped_legacy_logouts} expired/legacy)",
    )
    print(f"  Username case collisions:    {summary.username_collisions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
