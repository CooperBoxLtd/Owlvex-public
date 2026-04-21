import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.db.models import Comparison, Customer, Licence, LicenceSeat, ScanHistory, TeamPrompt, UsageEvent
from app.db.session import get_db
from app.services.email_service import send_verification_email
from app.services.licence_service import generate_licence_key, hash_licence_key

router = APIRouter(prefix="/v1/admin", tags=["admin"])
ADMIN_APP_PATH = Path(__file__).resolve().parents[1] / "static" / "admin-console.html"


class ResendVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class CustomerLicenceActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    plan: str | None = Field(default=None, pattern="^(free|trial|developer|team|enterprise)$")


class CustomerTelemetryRequest(CustomerLicenceActionRequest):
    enabled: bool


class BanCustomerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    reason: str | None = Field(default=None, max_length=500)


class DeleteCustomerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr


class DeleteLicenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    licence_id: str


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


def _serialize_licence(licence: Licence) -> dict:
    return {
        "licence_id": str(licence.id),
        "customer_id": str(licence.customer_id) if licence.customer_id else None,
        "team_name": licence.team_name,
        "plan": licence.plan,
        "email": licence.email,
        "is_active": bool(licence.is_active),
        "created_at": licence.created_at.isoformat() if licence.created_at else None,
        "updated_at": licence.updated_at.isoformat() if licence.updated_at else None,
        "expires_at": licence.expires_at.isoformat() if licence.expires_at else None,
        "seats": licence.seats,
        "seats_used": licence.seats_used,
        "features": licence.features or {},
        "industry_packs": licence.industry_packs or [],
        "stripe_customer_id": licence.stripe_customer_id,
        "stripe_subscription_id": licence.stripe_subscription_id,
    }


def _serialize_customer(customer: Customer) -> dict:
    return {
        "customer_id": str(customer.id),
        "email": customer.email,
        "name": customer.name,
        "company": customer.company,
        "source": customer.source,
        "pending_plan": customer.pending_plan,
        "is_banned": bool(customer.is_banned),
        "banned_at": customer.banned_at.isoformat() if customer.banned_at else None,
        "ban_reason": customer.ban_reason,
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


def _serialize_scan(scan: ScanHistory) -> dict:
    return {
        "scan_id": str(scan.id),
        "licence_id": str(scan.licence_id),
        "user_email": scan.user_email,
        "file_name": scan.file_name,
        "file_hash": scan.file_hash,
        "language": scan.language,
        "model": scan.model,
        "provider": scan.provider,
        "frameworks": scan.frameworks or [],
        "score": scan.score,
        "finding_count": scan.finding_count,
        "findings_summary": scan.findings_summary or {},
        "token_count": scan.token_count,
        "duration_ms": scan.duration_ms,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


def _serialize_usage_event(event: UsageEvent) -> dict:
    return {
        "event_id": str(event.id),
        "licence_id": str(event.licence_id),
        "user_email": event.user_email,
        "event_name": event.event_name,
        "metadata": event.event_data or {},
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


def _serialize_comparison(item: Comparison) -> dict:
    return {
        "comparison_id": str(item.id),
        "licence_id": str(item.licence_id),
        "scan_a_id": str(item.scan_a_id),
        "scan_b_id": str(item.scan_b_id),
        "score_change": item.score_change,
        "new_findings": item.new_findings,
        "resolved_findings": item.resolved_findings,
        "diff_summary": item.diff_summary or {},
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


async def _purge_licence_tree(db: AsyncSession, licence: Licence) -> None:
    await db.execute(delete(Comparison).where(Comparison.licence_id == licence.id))
    await db.execute(delete(ScanHistory).where(ScanHistory.licence_id == licence.id))
    await db.execute(delete(UsageEvent).where(UsageEvent.licence_id == licence.id))
    await db.execute(delete(LicenceSeat).where(LicenceSeat.licence_id == licence.id))
    await db.execute(delete(TeamPrompt).where(TeamPrompt.licence_id == licence.id))
    await db.execute(delete(Licence).where(Licence.id == licence.id))


async def _purge_customer_tree(db: AsyncSession, customer: Customer) -> int:
    result = await db.execute(select(Licence).where(Licence.customer_id == customer.id))
    licences = result.scalars().all()
    deleted_licences = 0
    for licence in licences:
        await _purge_licence_tree(db, licence)
        deleted_licences += 1
    await db.execute(delete(Customer).where(Customer.id == customer.id))
    return deleted_licences


@router.get("/app", response_class=HTMLResponse)
async def admin_app() -> FileResponse:
    return FileResponse(ADMIN_APP_PATH)


@router.get("/overview")
async def overview(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    limit: int = Query(default=100, ge=1, le=1000),
    q: str | None = Query(default=None, max_length=200),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    query = select(Customer).options(selectinload(Customer.licences)).order_by(Customer.created_at.desc())
    if q:
        q_lower = f"%{q.lower()}%"
        query = query.where(
            Customer.email.ilike(q_lower) | Customer.name.ilike(q_lower) | Customer.company.ilike(q_lower)
        )
    result = await db.execute(query.limit(limit))
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
    customer = await _get_customer_with_licences(db, email)
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    return _serialize_customer(customer)


@router.get("/export")
async def export_snapshot(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    scope: str = Query(default="full", pattern="^(customers|full)$"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)

    customers_result = await db.execute(
        select(Customer).options(selectinload(Customer.licences)).order_by(Customer.created_at.desc())
    )
    customers = customers_result.scalars().all()

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "customers": [_serialize_customer(customer) for customer in customers],
    }

    if scope == "full":
        licences_result = await db.execute(select(Licence).order_by(Licence.created_at.desc()))
        scans_result = await db.execute(select(ScanHistory).order_by(ScanHistory.created_at.desc()))
        usage_result = await db.execute(select(UsageEvent).order_by(UsageEvent.created_at.desc()))
        comparisons_result = await db.execute(select(Comparison).order_by(Comparison.created_at.desc()))
        payload.update({
            "licences": [_serialize_licence(item) for item in licences_result.scalars().all()],
            "scans": [_serialize_scan(item) for item in scans_result.scalars().all()],
            "usage_events": [_serialize_usage_event(item) for item in usage_result.scalars().all()],
            "comparisons": [_serialize_comparison(item) for item in comparisons_result.scalars().all()],
        })

    return payload


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
    if customer.is_banned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Customer is banned")
    if not customer.pending_plan:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Customer has no pending verification")

    verification_code = _generate_verification_code()
    customer.verification_code_hash = _hash_verification_code(verification_code)
    customer.verification_code_expires_at = (
        datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=settings.email_verification_code_minutes)
    )

    if settings.resend_api_key:
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
        "delivery": "email" if settings.resend_api_key else "development_inline",
        "expires_in_minutes": settings.email_verification_code_minutes,
    }
    if not settings.resend_api_key and settings.is_development:
        response["verification_code"] = verification_code
    return response


@router.post("/customer/ban")
async def ban_customer(
    body: BanCustomerRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    customer.is_banned = True
    customer.banned_at = datetime.now(timezone.utc)
    customer.ban_reason = body.reason
    customer.pending_plan = None
    customer.verification_code_hash = None
    customer.verification_code_expires_at = None

    deactivated = 0
    for licence in customer.licences:
        if licence.is_active:
            licence.is_active = False
            deactivated += 1

    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "is_banned": True,
        "deactivated_licences": deactivated,
        "reason": body.reason,
    }


@router.post("/customer/unban")
async def unban_customer(
    body: BanCustomerRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    customer.is_banned = False
    customer.banned_at = None
    customer.ban_reason = None
    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "is_banned": False,
    }


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
    if customer.is_banned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Customer is banned")
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


@router.post("/licence/telemetry")
async def update_licence_telemetry(
    body: CustomerTelemetryRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    licences = _filter_customer_licences(customer, body.plan)
    if not licences:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No licence found for this customer")

    updated = 0
    applied_enabled = body.enabled
    for licence in licences:
        if licence.plan in {"free", "trial"} and not body.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Free and trial licences require telemetry and cannot disable it.",
            )
        features = dict(licence.features or {})
        features["telemetry_required"] = licence.plan in {"free", "trial"}
        features["telemetry_opt_out"] = licence.plan not in {"free", "trial"}
        features["telemetry_enabled"] = True if licence.plan in {"free", "trial"} else body.enabled
        licence.features = features
        applied_enabled = bool(features["telemetry_enabled"])
        updated += 1

    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "plan": body.plan,
        "telemetry_enabled": applied_enabled,
        "updated": updated,
    }


@router.post("/licence/delete")
async def delete_licence(
    body: DeleteLicenceRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    try:
        licence_uuid = uuid.UUID(body.licence_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid licence_id") from exc

    result = await db.execute(select(Licence).where(Licence.id == licence_uuid))
    licence = result.scalar_one_or_none()
    if not licence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Licence not found")

    licence_id = str(licence.id)
    email = licence.email
    await _purge_licence_tree(db, licence)
    await db.commit()
    return {
        "ok": True,
        "licence_id": licence_id,
        "email": email,
        "deleted": True,
    }


@router.post("/customer/delete")
async def delete_customer(
    body: DeleteCustomerRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    deleted_licences = await _purge_customer_tree(db, customer)
    await db.commit()
    return {
        "ok": True,
        "email": str(body.email),
        "deleted": True,
        "deleted_licences": deleted_licences,
    }
