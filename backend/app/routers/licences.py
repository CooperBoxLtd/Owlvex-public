import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.db.models import Customer, CustomerIdentity, Licence
from app.services.licence_service import (
    validate_licence,
    generate_licence_key,
    get_licence_by_key,
    hash_licence_key,
    record_seat_seen,
)
from app.services.rate_limit import allow_control_plane_request
from app.services.email_service import send_licence_issued_email, send_verification_email
from app.services.registration_funnel_service import record_registration_funnel_event
from app.config import get_settings

router = APIRouter(prefix="/v1/licences", tags=["licences"])
settings = get_settings()


async def _run_email_delivery(send_func, **kwargs) -> None:
    current_settings = get_settings()
    timeout_seconds = max(1.0, current_settings.email_delivery_timeout_seconds + 1.0)
    try:
        await asyncio.wait_for(
            asyncio.to_thread(send_func, **kwargs),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        raise RuntimeError("Email delivery request timed out") from exc


# ----------------------------------------------------------------
# POST /v1/licences/validate
# Called by VS Code extension on startup
# ----------------------------------------------------------------
class ValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_email: Optional[str] = None


@router.post("/validate")
async def validate(
    request: Request,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
    body: ValidateRequest = ValidateRequest(),
):
    if not allow_control_plane_request(
        "licence_validate",
        request,
        limit=settings.licence_validate_rate_limit,
        window_seconds=settings.rate_limit_window_seconds,
        licence_key=x_licence_key,
        trust_forwarded_for=settings.trust_forwarded_for,
    ):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many licence validation requests")

    result = await validate_licence(db, x_licence_key)

    if not result["valid"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=result["reason"])

    if body.user_email:
        await record_seat_seen(db, result["licence_id"], body.user_email)

    return result


# ----------------------------------------------------------------
# POST /v1/licences/generate
# Admin-only — creates a new licence (called after Stripe checkout)
# ----------------------------------------------------------------
class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    team_name: str
    email: EmailStr
    plan: str
    seats: int = Field(default=1, ge=1)
    expires_at: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    plan: str = Field(pattern="^(free|trial)$")
    name: Optional[str] = None
    company: Optional[str] = None


class VerifyRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    code: str = Field(min_length=4, max_length=32)


class UpdateTelemetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


PLAN_FEATURES = {
    "free": {
        "frameworks": ["OWASP"],
        "scans_per_month": 50,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": False,
        "ci_cd": False,
        "pdf_reports": False,
        "custom_rules": False,
        "sso": False,
        "telemetry_required": True,
        "telemetry_enabled": True,
        "telemetry_opt_out": False,
    },
    "trial": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS"],
        "scans_per_month": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": True,
        "ci_cd": True,
        "pdf_reports": True,
        "custom_rules": False,
        "sso": False,
        "telemetry_required": True,
        "telemetry_enabled": True,
        "telemetry_opt_out": False,
    },
    "developer": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE"],
        "scans_per_month": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": False,
        "ci_cd": False,
        "pdf_reports": False,
        "custom_rules": False,
        "sso": False,
        "telemetry_required": False,
        "telemetry_enabled": True,
        "telemetry_opt_out": True,
    },
    "team": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS"],
        "scans_per_month": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": True,
        "ci_cd": True,
        "pdf_reports": True,
        "custom_rules": False,
        "sso": False,
        "telemetry_required": False,
        "telemetry_enabled": True,
        "telemetry_opt_out": True,
    },
    "enterprise": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS", "HIPAA"],
        "scans_per_month": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": True,
        "ci_cd": True,
        "pdf_reports": True,
        "custom_rules": True,
        "sso": True,
        "telemetry_required": False,
        "telemetry_enabled": True,
        "telemetry_opt_out": True,
    },
}


def _default_team_name_for_registration(email: str, company: Optional[str], name: Optional[str]) -> str:
    if company and company.strip():
        return company.strip()
    if name and name.strip():
        return f"{name.strip()}'s Workspace"
    return email.split("@", 1)[0]


def _normalize_email(email: str) -> str:
    return email.strip().lower()


async def _get_or_create_customer(
    db: AsyncSession,
    *,
    email: str,
    name: Optional[str],
    company: Optional[str],
    source: str = "extension",
) -> Customer:
    email = _normalize_email(email)
    result = await db.execute(select(Customer).where(Customer.email == email))
    customer = result.scalar_one_or_none()
    if customer:
        if customer.is_banned:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This customer is banned.")
        if name:
            customer.name = name
        if company:
            customer.company = company
        return customer

    customer = Customer(
        email=email,
        name=name,
        company=company,
        source=source,
    )
    db.add(customer)
    await db.flush()
    return customer


async def _get_or_create_customer_identity(
    db: AsyncSession,
    *,
    email: str,
) -> CustomerIdentity:
    normalized_email = _normalize_email(email)
    result = await db.execute(select(CustomerIdentity).where(CustomerIdentity.email == normalized_email))
    identity = result.scalar_one_or_none()
    if identity:
        return identity

    identity = CustomerIdentity(email=normalized_email)
    db.add(identity)
    await db.flush()
    return identity


async def _discard_orphan_customer_identity(db: AsyncSession, *, identity: CustomerIdentity, email: str) -> bool:
    normalized_email = _normalize_email(email)
    result = await db.execute(select(Customer.id).where(Customer.email == normalized_email))
    if result.scalar_one_or_none():
        return False

    await db.execute(delete(CustomerIdentity).where(CustomerIdentity.email == normalized_email))
    if identity in db:
        db.expunge(identity)
    await db.flush()
    return True


async def _deactivate_existing_plan_licences(db: AsyncSession, *, email: str, plan: str) -> None:
    email = _normalize_email(email)
    result = await db.execute(
        select(Licence).where(
            Licence.email == email,
            Licence.plan == plan,
            Licence.is_active.is_(True),
        )
    )
    for licence in result.scalars().all():
        licence.is_active = False


def _generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash_verification_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _coerce_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _build_registration_response(
    *,
    email: str,
    plan: str,
    verification_code: str | None,
    settings,
) -> dict:
    response = {
        "status": "verification_required",
        "email": email,
        "plan": plan,
        "delivery": "email" if settings.resend_api_key else "development_inline",
        "expires_in_minutes": settings.email_verification_code_minutes,
    }
    if not settings.resend_api_key and settings.is_development and verification_code:
        response["verification_code"] = verification_code
    return response


@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate(
    body: GenerateRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    if x_admin_key != current_settings.admin_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin key")

    if body.plan not in PLAN_FEATURES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown plan: {body.plan}")

    normalized_email = _normalize_email(str(body.email))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    customer = await _get_or_create_customer(
        db,
        email=normalized_email,
        name=None,
        company=body.team_name,
        source="admin",
    )
    if not customer.email_verified_at:
        customer.email_verified_at = now

    raw_key = generate_licence_key()
    key_hash = hash_licence_key(raw_key)

    expires_dt = None
    if body.expires_at:
        try:
            expires_dt = datetime.fromisoformat(body.expires_at)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            if expires_dt <= datetime.now(timezone.utc):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be a valid ISO 8601 datetime")

    licence = Licence(
        customer_id=customer.id,
        licence_key_hash=key_hash,
        team_name=body.team_name,
        email=normalized_email,
        plan=body.plan,
        seats=body.seats,
        features=PLAN_FEATURES[body.plan],
        stripe_customer_id=body.stripe_customer_id,
        stripe_subscription_id=body.stripe_subscription_id,
        expires_at=expires_dt,
    )
    db.add(licence)
    await db.commit()
    await db.refresh(licence)

    return {
        "licence_id": str(licence.id),
        "licence_key": raw_key,   # returned ONCE — never retrievable again
        "plan": licence.plan,
        "team_name": licence.team_name,
        "email": licence.email,
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    normalized_email = _normalize_email(str(body.email))
    if not allow_control_plane_request(
        "licence_register",
        request,
        limit=current_settings.licence_register_rate_limit,
        window_seconds=current_settings.rate_limit_window_seconds,
        trust_forwarded_for=current_settings.trust_forwarded_for,
    ):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many registration requests")

    plan = body.plan.lower()
    if plan not in {"free", "trial"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only free and trial registration are supported here")

    identity = await _get_or_create_customer_identity(db, email=normalized_email)
    if plan == "trial" and identity.trial_activated_at and current_settings.environment != "development":
        if await _discard_orphan_customer_identity(db, identity=identity, email=normalized_email):
            identity = await _get_or_create_customer_identity(db, email=normalized_email)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="A trial has already been activated for this email.",
            )

    if plan == "trial" and identity.trial_activated_at and current_settings.environment != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A trial has already been activated for this email.",
        )

    customer = await _get_or_create_customer(
        db,
        email=normalized_email,
        name=body.name,
        company=body.company,
    )
    verification_code = _generate_verification_code()
    customer.pending_plan = plan
    customer.verification_code_hash = _hash_verification_code(verification_code)
    customer.verification_code_expires_at = (
        datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=current_settings.email_verification_code_minutes)
    )

    delivery = "email" if current_settings.resend_api_key else "development_inline"
    await record_registration_funnel_event(
        db,
        customer_id=customer.id,
        email=normalized_email,
        plan=plan,
        event_name="registration_started",
        delivery=delivery,
    )
    await db.commit()

    if current_settings.resend_api_key:
        try:
            await _run_email_delivery(
                send_verification_email,
                to_email=normalized_email,
                verification_code=verification_code,
                plan=plan,
            )
        except RuntimeError as exc:
            await record_registration_funnel_event(
                db,
                customer_id=customer.id,
                email=normalized_email,
                plan=plan,
                event_name="verification_delivery_failed",
                delivery=delivery,
            )
            await db.commit()
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    elif not current_settings.is_development:
        await record_registration_funnel_event(
            db,
            customer_id=customer.id,
            email=normalized_email,
            plan=plan,
            event_name="verification_delivery_failed",
            delivery=delivery,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification delivery is not configured.",
        )

    await record_registration_funnel_event(
        db,
        customer_id=customer.id,
        email=normalized_email,
        plan=plan,
        event_name="verification_sent",
        delivery=delivery,
    )
    await db.commit()
    return _build_registration_response(
        email=normalized_email,
        plan=plan,
        verification_code=verification_code,
        settings=current_settings,
    )


@router.post("/verify-email", status_code=status.HTTP_201_CREATED)
async def verify_email_registration(
    body: VerifyRegistrationRequest,
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    normalized_email = _normalize_email(str(body.email))
    result = await db.execute(select(Customer).where(Customer.email == normalized_email))
    customer = result.scalar_one_or_none()
    if not customer or not customer.verification_code_hash or not customer.pending_plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No pending registration found for this email")
    if customer.is_banned:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This customer is banned.")

    now = datetime.now(timezone.utc)
    expires_at = _coerce_utc(customer.verification_code_expires_at)
    if not expires_at or expires_at < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code has expired")

    if _hash_verification_code(body.code.strip()) != customer.verification_code_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code is invalid")

    plan = customer.pending_plan
    identity = await _get_or_create_customer_identity(db, email=customer.email)
    if plan == "trial" and identity.trial_activated_at and current_settings.environment != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A trial has already been activated for this email.",
        )
    await _deactivate_existing_plan_licences(db, email=customer.email, plan=plan)

    raw_key = generate_licence_key()
    key_hash = hash_licence_key(raw_key)
    team_name = _default_team_name_for_registration(customer.email, customer.company, customer.name)
    expires_dt = None
    if plan == "trial" and current_settings.environment != "development":
        expires_dt = now.replace(microsecond=0) + timedelta(days=7)

    customer.email_verified_at = now
    customer.verification_code_hash = None
    customer.verification_code_expires_at = None
    customer.pending_plan = None
    if plan == "trial" and not identity.trial_activated_at:
        identity.trial_activated_at = now
    if plan == "free" and not identity.free_activated_at:
        identity.free_activated_at = now

    licence = Licence(
        customer_id=customer.id,
        licence_key_hash=key_hash,
        team_name=team_name,
        email=customer.email,
        plan=plan,
        seats=1,
        features=PLAN_FEATURES[plan],
        expires_at=expires_dt,
    )
    db.add(licence)
    await record_registration_funnel_event(
        db,
        customer_id=customer.id,
        email=customer.email,
        plan=plan,
        event_name="verification_completed",
    )
    await record_registration_funnel_event(
        db,
        customer_id=customer.id,
        email=customer.email,
        plan=plan,
        event_name="licence_issued",
    )
    await db.commit()
    await db.refresh(licence)

    if current_settings.resend_api_key:
        try:
            await _run_email_delivery(
                send_licence_issued_email,
                to_email=licence.email,
                team_name=licence.team_name,
                plan=licence.plan,
                expires_at=licence.expires_at.isoformat() if licence.expires_at else None,
            )
        except RuntimeError:
            pass

    return {
        "customer_id": str(customer.id),
        "licence_id": str(licence.id),
        "licence_key": raw_key,
        "plan": licence.plan,
        "team_name": licence.team_name,
        "email": licence.email,
        "expires_at": licence.expires_at.isoformat() if licence.expires_at else None,
    }


@router.post("/telemetry")
async def update_telemetry_settings(
    body: UpdateTelemetryRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    licence = await get_licence_by_key(db, x_licence_key)
    if not licence:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Licence key not found")
    if not licence.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Licence is inactive")
    if licence.expires_at and licence.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Licence has expired")

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
    await db.commit()

    return {
        "ok": True,
        "licence_id": str(licence.id),
        "plan": licence.plan,
        "telemetry_enabled": bool(features["telemetry_enabled"]),
        "telemetry_required": bool(features["telemetry_required"]),
    }
