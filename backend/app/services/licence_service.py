import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Licence, LicenceSeat, UsageEvent


def hash_licence_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_licence_key() -> str:
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"owlvex_lic_{random_part}"


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

    if licence.expires_at and licence.expires_at < datetime.now(timezone.utc):
        return {"valid": False, "reason": "Licence has expired"}

    features = licence.features or {}
    allowed_frameworks = features.get("frameworks", ["OWASP"])
    scans_per_day = features.get("scans_per_day")
    scans_today = await get_daily_usage_count(db, str(licence.id), "scan_run")
    scans_remaining = None if scans_per_day is None else max(scans_per_day - scans_today, 0)

    return {
        "valid": True,
        "licence_id": str(licence.id),
        "team_name": licence.team_name,
        "plan": licence.plan,
        "seats": licence.seats,
        "seats_used": licence.seats_used,
        "features": {
            "frameworks": allowed_frameworks,
            "scans_per_day": scans_per_day,
            "prompt_editor": features.get("prompt_editor", False),
            "comparison": features.get("comparison", False),
            "team_prompts": features.get("team_prompts", False),
            "ci_cd": features.get("ci_cd", False),
            "pdf_reports": features.get("pdf_reports", False),
            "custom_rules": features.get("custom_rules", False),
            "sso": features.get("sso", False),
            "industry_packs": licence.industry_packs or [],
        },
        "usage": {
            "scans_today": scans_today,
            "scans_remaining": scans_remaining,
            "daily_limit_reached": scans_per_day is not None and scans_today >= scans_per_day,
        },
        "expires_at": licence.expires_at.isoformat() if licence.expires_at else None,
    }


async def get_daily_usage_count(db: AsyncSession, licence_id: str, event_name: str) -> int:
    start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    result = await db.execute(
        select(func.count())
        .select_from(UsageEvent)
        .where(
            UsageEvent.licence_id == licence_id,
            UsageEvent.event_name == event_name,
            UsageEvent.created_at >= start_of_day,
        )
    )
    return int(result.scalar_one() or 0)


async def record_seat_seen(db: AsyncSession, licence_id: str, user_email: str) -> None:
    result = await db.execute(
        select(LicenceSeat).where(
            LicenceSeat.licence_id == licence_id,
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
        lic_result = await db.execute(select(Licence).where(Licence.id == licence_id))
        licence = lic_result.scalar_one_or_none()
        if licence and licence.seats_used >= licence.seats:
            return  # Seat limit reached — silently skip rather than error mid-scan
        new_seat = LicenceSeat(
            licence_id=licence_id,
            user_email=user_email,
            last_seen=datetime.now(timezone.utc),
        )
        db.add(new_seat)
        # Atomic increment via SQL expression avoids read-modify-write race
        await db.execute(
            update(Licence)
            .where(Licence.id == licence_id)
            .values(seats_used=Licence.seats_used + 1)
        )

    await db.commit()
