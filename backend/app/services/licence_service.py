import hashlib
import inspect
import secrets
import string
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Customer, Licence, LicenceSeat, UsageEvent


def is_telemetry_required(features: dict | None) -> bool:
    return bool((features or {}).get("telemetry_required", False))


def is_telemetry_enabled(features: dict | None) -> bool:
    feature_map = features or {}
    if is_telemetry_required(feature_map):
        return True
    return bool(feature_map.get("telemetry_enabled", True))


def hash_licence_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_licence_key() -> str:
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"owlvex_lic_{random_part}"


def _coerce_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: str | uuid.UUID) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def get_licence_by_key(db: AsyncSession, raw_key: str) -> Optional[Licence]:
    key_hash = hash_licence_key(raw_key)
    result = await db.execute(
        select(Licence).where(Licence.licence_key_hash == key_hash)
    )
    return result.scalar_one_or_none()


async def validate_licence(db: AsyncSession, raw_key: str) -> dict:
    licence = await get_licence_by_key(db, raw_key)

    if not licence:
        return {"valid": False, "reason": "Licence key not found"}

    if not licence.is_active:
        return {"valid": False, "reason": "Licence is inactive"}

    expires_at = _coerce_utc(licence.expires_at)
    if expires_at and expires_at < datetime.now(timezone.utc):
        return {"valid": False, "reason": "Licence has expired"}

    if licence.customer_id:
        customer_result = await db.execute(select(Customer).where(Customer.id == licence.customer_id))
        customer = customer_result.scalar_one_or_none()
        if inspect.isawaitable(customer):
            customer = await customer
        if customer and customer.is_banned:
            return {"valid": False, "reason": "Customer is banned"}

    features = licence.features or {}
    allowed_frameworks = features.get("frameworks", ["OWASP"])
    scans_per_month = features.get("scans_per_month", features.get("scans_per_day"))
    scans_this_month = await get_monthly_usage_count(db, str(licence.id), "scan_run")
    scans_remaining = None if scans_per_month is None else max(scans_per_month - scans_this_month, 0)

    return {
        "valid": True,
        "licence_id": str(licence.id),
        "team_name": licence.team_name,
        "plan": licence.plan,
        "seats": licence.seats,
        "seats_used": licence.seats_used,
        "features": {
            "frameworks": allowed_frameworks,
            "scans_per_month": scans_per_month,
            "scans_per_day": scans_per_month,
            "prompt_editor": features.get("prompt_editor", False),
            "comparison": features.get("comparison", False),
            "team_prompts": features.get("team_prompts", False),
            "ci_cd": features.get("ci_cd", False),
            "pdf_reports": features.get("pdf_reports", False),
            "custom_rules": features.get("custom_rules", False),
            "sso": features.get("sso", False),
            "industry_packs": licence.industry_packs or [],
            "telemetry_required": is_telemetry_required(features),
            "telemetry_enabled": is_telemetry_enabled(features),
            "telemetry_opt_out": bool(features.get("telemetry_opt_out", False)),
            "telemetry_profile": features.get("telemetry_profile", "standard"),
        },
        "usage": {
            "scans_this_month": scans_this_month,
            "scans_today": scans_this_month,
            "scans_remaining": scans_remaining,
            "monthly_limit_reached": scans_per_month is not None and scans_this_month >= scans_per_month,
            "daily_limit_reached": scans_per_month is not None and scans_this_month >= scans_per_month,
        },
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


async def get_monthly_usage_count(db: AsyncSession, licence_id: str, event_name: str) -> int:
    licence_uuid = _coerce_uuid(licence_id)
    now = datetime.now(timezone.utc)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    result = await db.execute(
        select(func.count())
        .select_from(UsageEvent)
        .where(
            UsageEvent.licence_id == licence_uuid,
            UsageEvent.event_name == event_name,
            UsageEvent.created_at >= start_of_month,
        )
    )
    count = result.scalar_one()
    if inspect.isawaitable(count):
        count = await count
    return int(count or 0)


async def record_seat_seen(db: AsyncSession, licence_id: str, user_email: str) -> None:
    licence_uuid = _coerce_uuid(licence_id)
    result = await db.execute(
        select(LicenceSeat).where(
            LicenceSeat.licence_id == licence_uuid,
            LicenceSeat.user_email == user_email,
        )
    )
    seat = result.scalar_one_or_none()

    if seat:
        await db.execute(
            update(LicenceSeat)
            .where(LicenceSeat.id == seat.id)
            .values(last_seen=datetime.now(timezone.utc))
        )
    else:
        # Enforce seat limit before allocating a new seat
        lic_result = await db.execute(select(Licence).where(Licence.id == licence_uuid))
        licence = lic_result.scalar_one_or_none()
        if licence and licence.seats_used >= licence.seats:
            return  # Seat limit reached — silently skip rather than error mid-scan
        new_seat = LicenceSeat(
            licence_id=licence_uuid,
            user_email=user_email,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(new_seat)
        # Atomic increment via SQL expression avoids read-modify-write race
        await db.execute(
            update(Licence)
            .where(Licence.id == licence_uuid)
            .values(seats_used=Licence.seats_used + 1)
        )

    await db.commit()
