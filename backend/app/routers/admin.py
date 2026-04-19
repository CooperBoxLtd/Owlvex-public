import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.db.models import Customer, Licence
from app.db.session import get_db
from app.services.email_service import send_verification_email
from app.services.licence_service import generate_licence_key, hash_licence_key

router = APIRouter(prefix="/v1/admin", tags=["admin"])


class ResendVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class CustomerLicenceActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    plan: str | None = Field(default=None, pattern="^(free|trial|developer|team|enterprise)$")


def _ensure_admin_key(x_admin_key: str) -> None:
    settings = get_settings()
    if x_admin_key != settings.admin_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin key")


def _generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash_verification_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


async def _get_customer_with_licences(db: AsyncSession, email: str) -> Customer | None:
    result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.licences))
        .where(Customer.email == email)
    )
    return result.scalar_one_or_none()


def _filter_customer_licences(customer: Customer, plan: str | None) -> list[Licence]:
    licences = list(customer.licences)
    if plan:
        licences = [licence for licence in licences if licence.plan == plan]
    return sorted(licences, key=lambda item: item.created_at or 0, reverse=True)


def _serialize_licence(licence) -> dict:
    return {
        "licence_id": str(licence.id),
        "team_name": licence.team_name,
        "plan": licence.plan,
        "email": licence.email,
        "is_active": bool(licence.is_active),
        "created_at": licence.created_at.isoformat() if licence.created_at else None,
        "expires_at": licence.expires_at.isoformat() if licence.expires_at else None,
        "seats": licence.seats,
        "seats_used": licence.seats_used,
    }


def _serialize_customer(customer) -> dict:
    return {
        "customer_id": str(customer.id),
        "email": customer.email,
        "name": customer.name,
        "company": customer.company,
        "source": customer.source,
        "pending_plan": customer.pending_plan,
        "email_verified_at": customer.email_verified_at.isoformat() if customer.email_verified_at else None,
        "verification_pending": bool(customer.verification_code_hash),
        "verification_code_expires_at": customer.verification_code_expires_at.isoformat()
        if customer.verification_code_expires_at else None,
        "created_at": customer.created_at.isoformat() if customer.created_at else None,
        "updated_at": customer.updated_at.isoformat() if customer.updated_at else None,
        "licences": [_serialize_licence(licence) for licence in sorted(
            customer.licences,
            key=lambda item: item.created_at or 0,
            reverse=True,
        )],
    }


@router.get("/overview")
async def overview(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    limit: int = Query(default=25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.licences))
        .order_by(Customer.created_at.desc())
        .limit(limit)
    )
    customers = result.scalars().all()
    return {
        "count": len(customers),
        "customers": [_serialize_customer(customer) for customer in customers],
    }


@router.get("/customer")
async def customer_lookup(
    email: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.licences))
        .where(Customer.email == email)
    )
    customer = result.scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    return _serialize_customer(customer)


@router.post("/resend-verification")
async def resend_verification(
    body: ResendVerificationRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    if not customer.pending_plan:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Customer has no pending verification")

    verification_code = _generate_verification_code()
    customer.verification_code_hash = _hash_verification_code(verification_code)
    customer.verification_code_expires_at = (
        datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=settings.email_verification_code_minutes)
    )

    if settings.sendgrid_api_key:
        try:
            send_verification_email(
                to_email=customer.email,
                verification_code=verification_code,
                plan=customer.pending_plan,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    elif not settings.is_development:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Email delivery is not configured.")

    await db.commit()
    response = {
        "ok": True,
        "email": customer.email,
        "pending_plan": customer.pending_plan,
        "delivery": "email" if settings.sendgrid_api_key else "development_inline",
        "expires_in_minutes": settings.email_verification_code_minutes,
    }
    if not settings.sendgrid_api_key and settings.is_development:
        response["verification_code"] = verification_code
    return response


@router.post("/licence/deactivate")
async def deactivate_licence(
    body: CustomerLicenceActionRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    licences = [licence for licence in _filter_customer_licences(customer, body.plan) if licence.is_active]
    if not licences:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active licence found for this customer")

    for licence in licences:
        licence.is_active = False

    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "deactivated": len(licences),
        "plan": body.plan,
    }


@router.post("/licence/rotate")
async def rotate_licence(
    body: CustomerLicenceActionRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    if not customer.email_verified_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Customer email is not verified")

    licences = _filter_customer_licences(customer, body.plan)
    if not licences:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No licence found for this customer")

    source_licence = licences[0]
    for licence in licences:
        if licence.is_active:
            licence.is_active = False

    raw_key = generate_licence_key()
    rotated = Licence(
        customer_id=customer.id,
        licence_key_hash=hash_licence_key(raw_key),
        team_name=source_licence.team_name,
        email=customer.email,
        plan=source_licence.plan,
        seats=source_licence.seats,
        seats_used=source_licence.seats_used,
        features=source_licence.features,
        industry_packs=source_licence.industry_packs,
        expires_at=source_licence.expires_at,
        is_active=True,
        stripe_customer_id=source_licence.stripe_customer_id,
        stripe_subscription_id=source_licence.stripe_subscription_id,
    )
    db.add(rotated)
    await db.commit()
    await db.refresh(rotated)

    return {
        "ok": True,
        "email": customer.email,
        "plan": rotated.plan,
        "licence_id": str(rotated.id),
        "licence_key": raw_key,
        "rotated_from_licence_id": str(source_licence.id),
    }
