import hashlib
import secrets
import uuid
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone, date
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import delete, func, select, and_, false, literal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.db.models import (
    AdminAuditLog,
    Comparison,
    Customer,
    CustomerIdentity,
    CustomerNote,
    Licence,
    LicenceSeat,
    RegistrationFunnelEvent,
    ScanHistory,
    TeamPrompt,
    UsageEvent,
)
from app.db.session import get_db
from app.services.admin_ops import record_admin_audit_event
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


class CustomerTelemetryProfileRequest(CustomerLicenceActionRequest):
    profile: str = Field(pattern="^(standard|dev_observability)$")


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


class CustomerNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    note: str = Field(min_length=1, max_length=4000)


class ExportRequestParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset: str
    format: str


def _ensure_admin_key(x_admin_key: str) -> None:
    settings = get_settings()
    if x_admin_key != settings.admin_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin key")


def _admin_actor(x_admin_actor: str | None) -> str:
    value = (x_admin_actor or "").strip()
    return value or "unknown-operator"


def _parse_date_filter(value: str | None, *, inclusive_end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        try:
            parsed_date = date.fromisoformat(value)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid date filter: {value}",
            ) from exc
        parsed = datetime.combine(parsed_date, datetime.min.time(), tzinfo=timezone.utc)
        if inclusive_end:
            parsed = parsed + timedelta(days=1)
        return parsed

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    if inclusive_end and "T" not in value:
        parsed = parsed + timedelta(days=1)
    return parsed


def _apply_date_range(query, column, *, date_from: datetime | None, date_to: datetime | None):
    conditions = []
    if date_from:
        conditions.append(column >= date_from)
    if date_to:
        conditions.append(column < date_to)
    if conditions:
        query = query.where(and_(*conditions))
    return query


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


def _base_customer_summary(customer: Customer) -> dict:
    active_licences = [licence for licence in customer.licences if licence.is_active]
    latest_active = next(
        iter(sorted(active_licences, key=lambda item: item.created_at or 0, reverse=True)),
        None,
    )
    telemetry_enabled = [
        bool((licence.features or {}).get("telemetry_enabled", True))
        for licence in customer.licences
        if licence.plan not in {"free", "trial"}
    ]
    return {
        "licence_count": len(customer.licences),
        "active_licence_count": len(active_licences),
        "active_plan": latest_active.plan if latest_active else None,
        "verification_pending": bool(customer.verification_code_hash),
        "telemetry_enabled": all(telemetry_enabled) if telemetry_enabled else True,
        "scan_count": 0,
        "usage_event_count": 0,
        "comparison_count": 0,
        "last_scan_at": None,
        "last_usage_at": None,
        "last_comparison_at": None,
        "last_activity_at": None,
    }


def _merge_customer_summary(summary: dict, updates: dict | None) -> dict:
    merged = dict(summary)
    if updates:
        merged.update({key: value for key, value in updates.items() if value is not None})

    timestamps = [
        merged.get("last_scan_at"),
        merged.get("last_usage_at"),
        merged.get("last_comparison_at"),
    ]
    merged["last_activity_at"] = max((value for value in timestamps if value), default=None)
    return merged


def _serialize_customer(customer: Customer, summary: dict | None = None) -> dict:
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
        "summary": _merge_customer_summary(_base_customer_summary(customer), summary),
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


def _serialize_registration_funnel_event(event: RegistrationFunnelEvent) -> dict:
    return {
        "event_id": str(event.id),
        "customer_id": str(event.customer_id) if event.customer_id else None,
        "email": event.email,
        "plan": event.plan,
        "event_name": event.event_name,
        "delivery": event.delivery,
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


def _serialize_customer_note(note: CustomerNote) -> dict:
    return {
        "note_id": str(note.id),
        "customer_id": str(note.customer_id),
        "author": note.author,
        "note": note.note,
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None,
    }


def _serialize_audit_event(item: AdminAuditLog) -> dict:
    return {
        "audit_id": str(item.id),
        "customer_id": str(item.customer_id) if item.customer_id else None,
        "licence_id": str(item.licence_id) if item.licence_id else None,
        "customer_email": item.customer_email,
        "actor": item.actor,
        "action": item.action,
        "reason": item.reason,
        "environment": item.environment,
        "details": item.details or {},
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


async def _collect_customer_activity_summaries(
    db: AsyncSession,
    customers: list[Customer],
) -> dict[str, dict]:
    if not customers:
        return {}

    customer_ids = [customer.id for customer in customers]
    summaries: dict[str, dict] = defaultdict(dict)

    scan_result = await db.execute(
        select(
            Licence.customer_id,
            func.count(ScanHistory.id),
            func.max(ScanHistory.created_at),
        )
        .join(ScanHistory, ScanHistory.licence_id == Licence.id)
        .where(Licence.customer_id.in_(customer_ids))
        .group_by(Licence.customer_id)
    )
    for customer_id, count, last_at in scan_result.all():
        summaries[str(customer_id)]["scan_count"] = int(count or 0)
        summaries[str(customer_id)]["last_scan_at"] = last_at.isoformat() if last_at else None

    usage_result = await db.execute(
        select(
            Licence.customer_id,
            func.count(UsageEvent.id),
            func.max(UsageEvent.created_at),
        )
        .join(UsageEvent, UsageEvent.licence_id == Licence.id)
        .where(Licence.customer_id.in_(customer_ids))
        .group_by(Licence.customer_id)
    )
    for customer_id, count, last_at in usage_result.all():
        summaries[str(customer_id)]["usage_event_count"] = int(count or 0)
        summaries[str(customer_id)]["last_usage_at"] = last_at.isoformat() if last_at else None

    comparison_result = await db.execute(
        select(
            Licence.customer_id,
            func.count(Comparison.id),
            func.max(Comparison.created_at),
        )
        .join(Comparison, Comparison.licence_id == Licence.id)
        .where(Licence.customer_id.in_(customer_ids))
        .group_by(Licence.customer_id)
    )
    for customer_id, count, last_at in comparison_result.all():
        summaries[str(customer_id)]["comparison_count"] = int(count or 0)
        summaries[str(customer_id)]["last_comparison_at"] = last_at.isoformat() if last_at else None

    return summaries


async def _collect_recent_customer_activity(db: AsyncSession, customer: Customer) -> dict:
    licence_ids = [licence.id for licence in customer.licences]
    if not licence_ids:
        return {"recent_scans": [], "recent_usage_events": [], "recent_comparisons": []}

    scans_result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.licence_id.in_(licence_ids))
        .order_by(ScanHistory.created_at.desc())
        .limit(8)
    )
    usage_result = await db.execute(
        select(UsageEvent)
        .where(UsageEvent.licence_id.in_(licence_ids))
        .order_by(UsageEvent.created_at.desc())
        .limit(8)
    )
    comparisons_result = await db.execute(
        select(Comparison)
        .where(Comparison.licence_id.in_(licence_ids))
        .order_by(Comparison.created_at.desc())
        .limit(8)
    )

    return {
        "recent_scans": [_serialize_scan(item) for item in scans_result.scalars().all()],
        "recent_usage_events": [_serialize_usage_event(item) for item in usage_result.scalars().all()],
        "recent_comparisons": [_serialize_comparison(item) for item in comparisons_result.scalars().all()],
    }


async def _collect_customer_notes(db: AsyncSession, customer: Customer, *, limit: int = 20) -> list[dict]:
    result = await db.execute(
        select(CustomerNote)
        .where(CustomerNote.customer_id == customer.id)
        .order_by(CustomerNote.created_at.desc())
        .limit(limit)
    )
    return [_serialize_customer_note(item) for item in result.scalars().all()]


async def _collect_customer_audit_history(db: AsyncSession, customer: Customer, *, limit: int = 50) -> list[dict]:
    licence_ids = [licence.id for licence in customer.licences]
    query = (
        select(AdminAuditLog)
        .where(
            (AdminAuditLog.customer_id == customer.id)
            | (AdminAuditLog.customer_email == customer.email)
            | (AdminAuditLog.licence_id.in_(licence_ids) if licence_ids else false())
        )
        .order_by(AdminAuditLog.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    return [_serialize_audit_event(item) for item in result.scalars().all()]


def _csv_response(*, filename: str, rows: list[dict]) -> Response:
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write("")
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _metrics_summary(
    db: AsyncSession,
    *,
    date_from: datetime | None,
    date_to: datetime | None,
    plan: str | None,
) -> dict:
    customer_query = select(func.count(Customer.id))
    customer_query = _apply_date_range(customer_query, Customer.created_at, date_from=date_from, date_to=date_to)
    total_customers = int((await db.execute(customer_query)).scalar() or 0)

    verified_query = select(func.count(Customer.id)).where(Customer.email_verified_at.is_not(None))
    verified_query = _apply_date_range(verified_query, Customer.email_verified_at, date_from=date_from, date_to=date_to)
    verified_customers = int((await db.execute(verified_query)).scalar() or 0)

    banned_query = select(func.count(Customer.id)).where(Customer.is_banned.is_(True))
    banned_query = _apply_date_range(banned_query, Customer.updated_at, date_from=date_from, date_to=date_to)
    banned_customers = int((await db.execute(banned_query)).scalar() or 0)

    licence_query = select(func.count(Licence.id))
    if plan:
        licence_query = licence_query.where(Licence.plan == plan)
    licence_query = _apply_date_range(licence_query, Licence.created_at, date_from=date_from, date_to=date_to)
    licences_issued = int((await db.execute(licence_query)).scalar() or 0)

    active_licence_query = select(func.count(Licence.id)).where(Licence.is_active.is_(True))
    if plan:
        active_licence_query = active_licence_query.where(Licence.plan == plan)
    active_licence_query = _apply_date_range(
        active_licence_query,
        Licence.updated_at,
        date_from=date_from,
        date_to=date_to,
    )
    active_licences = int((await db.execute(active_licence_query)).scalar() or 0)

    scan_query = select(func.count(ScanHistory.id)).join(Licence, Licence.id == ScanHistory.licence_id)
    usage_query = select(func.count(UsageEvent.id)).join(Licence, Licence.id == UsageEvent.licence_id)
    comparison_query = select(func.count(Comparison.id)).join(Licence, Licence.id == Comparison.licence_id)
    if plan:
        scan_query = scan_query.where(Licence.plan == plan)
        usage_query = usage_query.where(Licence.plan == plan)
        comparison_query = comparison_query.where(Licence.plan == plan)
    scan_query = _apply_date_range(scan_query, ScanHistory.created_at, date_from=date_from, date_to=date_to)
    usage_query = _apply_date_range(usage_query, UsageEvent.created_at, date_from=date_from, date_to=date_to)
    comparison_query = _apply_date_range(comparison_query, Comparison.created_at, date_from=date_from, date_to=date_to)

    note_query = select(func.count(CustomerNote.id))
    note_query = _apply_date_range(note_query, CustomerNote.created_at, date_from=date_from, date_to=date_to)
    audit_query = select(func.count(AdminAuditLog.id))
    audit_query = _apply_date_range(audit_query, AdminAuditLog.created_at, date_from=date_from, date_to=date_to)

    return {
        "total_customers": total_customers,
        "verified_customers": verified_customers,
        "banned_customers": banned_customers,
        "licences_issued": licences_issued,
        "active_licences": active_licences,
        "scan_count": int((await db.execute(scan_query)).scalar() or 0),
        "usage_event_count": int((await db.execute(usage_query)).scalar() or 0),
        "comparison_count": int((await db.execute(comparison_query)).scalar() or 0),
        "customer_note_count": int((await db.execute(note_query)).scalar() or 0),
        "admin_audit_event_count": int((await db.execute(audit_query)).scalar() or 0),
    }


async def _metrics_funnel(
    db: AsyncSession,
    *,
    date_from: datetime | None,
    date_to: datetime | None,
    plan: str | None,
) -> dict:
    registration_query = select(func.count(RegistrationFunnelEvent.id)).where(
        RegistrationFunnelEvent.event_name == "registration_started"
    )
    if plan:
        registration_query = registration_query.where(RegistrationFunnelEvent.plan == plan)
    registration_query = _apply_date_range(
        registration_query,
        RegistrationFunnelEvent.created_at,
        date_from=date_from,
        date_to=date_to,
    )
    registrations_started = int((await db.execute(registration_query)).scalar() or 0)

    verification_query = select(func.count(RegistrationFunnelEvent.id)).where(
        RegistrationFunnelEvent.event_name == "verification_completed"
    )
    if plan:
        verification_query = verification_query.where(RegistrationFunnelEvent.plan == plan)
    verification_query = _apply_date_range(
        verification_query,
        RegistrationFunnelEvent.created_at,
        date_from=date_from,
        date_to=date_to,
    )
    verification_completed = int((await db.execute(verification_query)).scalar() or 0)

    licence_query = select(func.count(RegistrationFunnelEvent.id)).where(
        RegistrationFunnelEvent.event_name == "licence_issued"
    )
    if plan:
        licence_query = licence_query.where(RegistrationFunnelEvent.plan == plan)
    licence_query = _apply_date_range(
        licence_query,
        RegistrationFunnelEvent.created_at,
        date_from=date_from,
        date_to=date_to,
    )
    licences_issued = int((await db.execute(licence_query)).scalar() or 0)

    first_scan_subquery = (
        select(Licence.customer_id.label("customer_id"), func.min(ScanHistory.created_at).label("first_scan_at"))
        .join(ScanHistory, ScanHistory.licence_id == Licence.id)
        .where(Licence.customer_id.is_not(None))
        .group_by(Licence.customer_id)
        .subquery()
    )
    first_scan_query = select(func.count(first_scan_subquery.c.customer_id))
    first_scan_query = _apply_date_range(
        first_scan_query,
        first_scan_subquery.c.first_scan_at,
        date_from=date_from,
        date_to=date_to,
    )
    first_scan_completed = int((await db.execute(first_scan_query)).scalar() or 0)

    pending_query = select(func.count(Customer.id)).where(Customer.verification_code_hash.is_not(None))
    pending_query = _apply_date_range(pending_query, Customer.created_at, date_from=date_from, date_to=date_to)
    pending_verification = int((await db.execute(pending_query)).scalar() or 0)

    return {
        "registrations_started": registrations_started,
        "verification_completed": verification_completed,
        "licences_issued": licences_issued,
        "first_scan_completed": first_scan_completed,
        "pending_verification": pending_verification,
    }


async def _metrics_usage(
    db: AsyncSession,
    *,
    date_from: datetime | None,
    date_to: datetime | None,
    plan: str | None,
    group_by: str = "plan",
) -> dict:
    if group_by not in {"overall", "plan", "customer"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported group_by value: {group_by}")

    if group_by == "customer":
        group_value = func.coalesce(Customer.email, Licence.email)
        key_name = "customer"
        group_sources = (
            select(
                group_value.label("group_key"),
                Licence.plan.label("plan"),
                func.count(ScanHistory.id).label("scans"),
                func.count(func.distinct(Licence.customer_id)).label("active_customers"),
                func.sum(ScanHistory.finding_count).label("findings"),
            )
            .select_from(Licence)
            .join(ScanHistory, ScanHistory.licence_id == Licence.id)
            .outerjoin(Customer, Customer.id == Licence.customer_id)
            .group_by(group_value, Licence.plan)
        )
        comparison_query = (
            select(group_value.label("group_key"), Licence.plan.label("plan"), func.count(Comparison.id).label("comparisons"))
            .select_from(Licence)
            .join(Comparison, Comparison.licence_id == Licence.id)
            .outerjoin(Customer, Customer.id == Licence.customer_id)
            .group_by(group_value, Licence.plan)
        )
        usage_query = (
            select(group_value.label("group_key"), Licence.plan.label("plan"), func.count(UsageEvent.id).label("usage_events"))
            .select_from(Licence)
            .join(UsageEvent, UsageEvent.licence_id == Licence.id)
            .outerjoin(Customer, Customer.id == Licence.customer_id)
            .group_by(group_value, Licence.plan)
        )
    elif group_by == "overall":
        group_value = literal("overall")
        key_name = "group"
        group_sources = (
            select(
                group_value.label("group_key"),
                func.count(ScanHistory.id).label("scans"),
                func.count(func.distinct(Licence.customer_id)).label("active_customers"),
                func.sum(ScanHistory.finding_count).label("findings"),
            )
            .select_from(Licence)
            .join(ScanHistory, ScanHistory.licence_id == Licence.id)
            .group_by(group_value)
        )
        comparison_query = (
            select(group_value.label("group_key"), func.count(Comparison.id).label("comparisons"))
            .select_from(Licence)
            .join(Comparison, Comparison.licence_id == Licence.id)
            .group_by(group_value)
        )
        usage_query = (
            select(group_value.label("group_key"), func.count(UsageEvent.id).label("usage_events"))
            .select_from(Licence)
            .join(UsageEvent, UsageEvent.licence_id == Licence.id)
            .group_by(group_value)
        )
    else:
        group_value = Licence.plan
        key_name = "plan"
        group_sources = (
            select(
                group_value.label("group_key"),
                func.count(ScanHistory.id).label("scans"),
                func.count(func.distinct(Licence.customer_id)).label("active_customers"),
                func.sum(ScanHistory.finding_count).label("findings"),
            )
            .select_from(Licence)
            .join(ScanHistory, ScanHistory.licence_id == Licence.id)
            .group_by(group_value)
        )
        comparison_query = (
            select(group_value.label("group_key"), func.count(Comparison.id).label("comparisons"))
            .select_from(Licence)
            .join(Comparison, Comparison.licence_id == Licence.id)
            .group_by(group_value)
        )
        usage_query = (
            select(group_value.label("group_key"), func.count(UsageEvent.id).label("usage_events"))
            .select_from(Licence)
            .join(UsageEvent, UsageEvent.licence_id == Licence.id)
            .group_by(group_value)
        )

    if plan:
        group_sources = group_sources.where(Licence.plan == plan)
        comparison_query = comparison_query.where(Licence.plan == plan)
        usage_query = usage_query.where(Licence.plan == plan)
    group_sources = _apply_date_range(group_sources, ScanHistory.created_at, date_from=date_from, date_to=date_to)
    comparison_query = _apply_date_range(comparison_query, Comparison.created_at, date_from=date_from, date_to=date_to)
    usage_query = _apply_date_range(usage_query, UsageEvent.created_at, date_from=date_from, date_to=date_to)

    grouped_rows: dict[str, dict] = {}
    for row in (await db.execute(group_sources)).all():
        if group_by == "customer":
            group_key, item_plan, scans, active_customers, findings = row
            grouped_rows[str(group_key)] = {
                key_name: group_key,
                "plan": item_plan,
                "scans": int(scans or 0),
                "active_customers": int(active_customers or 0),
                "findings": int(findings or 0),
            }
        else:
            group_key, scans, active_customers, findings = row
            grouped_rows[str(group_key)] = {
                key_name: group_key,
                "scans": int(scans or 0),
                "active_customers": int(active_customers or 0),
                "findings": int(findings or 0),
            }

    for row in (await db.execute(comparison_query)).all():
        if group_by == "customer":
            group_key, item_plan, comparisons = row
            grouped_rows.setdefault(
                str(group_key),
                {key_name: group_key, "plan": item_plan, "scans": 0, "active_customers": 0, "findings": 0},
            )["comparisons"] = int(comparisons or 0)
        else:
            group_key, comparisons = row
            grouped_rows.setdefault(
                str(group_key),
                {key_name: group_key, "scans": 0, "active_customers": 0, "findings": 0},
            )["comparisons"] = int(comparisons or 0)

    for row in (await db.execute(usage_query)).all():
        if group_by == "customer":
            group_key, item_plan, usage_events = row
            grouped_rows.setdefault(
                str(group_key),
                {key_name: group_key, "plan": item_plan, "scans": 0, "active_customers": 0, "findings": 0},
            )["usage_events"] = int(usage_events or 0)
        else:
            group_key, usage_events = row
            grouped_rows.setdefault(
                str(group_key),
                {key_name: group_key, "scans": 0, "active_customers": 0, "findings": 0},
            )["usage_events"] = int(usage_events or 0)

    rows = []
    for item in grouped_rows.values():
        item.setdefault("comparisons", 0)
        item.setdefault("usage_events", 0)
        rows.append(item)

    if group_by == "customer":
        rows.sort(key=lambda item: (str(item.get("plan") or ""), str(item.get("customer") or "")))
    elif group_by == "plan":
        rows.sort(key=lambda item: str(item.get("plan") or ""))

    return {
        "group_by": group_by,
        "rows": rows,
        "totals": {
            "scans": sum(item["scans"] for item in rows),
            "active_customers": sum(item["active_customers"] for item in rows),
            "findings": sum(item["findings"] for item in rows),
            "comparisons": sum(item["comparisons"] for item in rows),
            "usage_events": sum(item["usage_events"] for item in rows),
        },
    }


async def _purge_licence_tree(db: AsyncSession, licence: Licence) -> None:
    await db.execute(delete(Comparison).where(Comparison.licence_id == licence.id))
    await db.execute(delete(ScanHistory).where(ScanHistory.licence_id == licence.id))
    await db.execute(delete(UsageEvent).where(UsageEvent.licence_id == licence.id))
    await db.execute(delete(LicenceSeat).where(LicenceSeat.licence_id == licence.id))
    await db.execute(delete(TeamPrompt).where(TeamPrompt.licence_id == licence.id))
    await db.execute(delete(Licence).where(Licence.id == licence.id))


async def _purge_customer_tree(db: AsyncSession, customer: Customer) -> int:
    customer_email = customer.email
    result = await db.execute(select(Licence).where(Licence.customer_id == customer.id))
    licences = result.scalars().all()
    deleted_licences = 0
    for licence in licences:
        await _purge_licence_tree(db, licence)
        deleted_licences += 1
    await db.execute(delete(Customer).where(Customer.id == customer.id))
    await db.execute(delete(CustomerIdentity).where(CustomerIdentity.email == customer_email))
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
    summaries = await _collect_customer_activity_summaries(db, customers)
    return {
        "count": len(customers),
        "customers": [_serialize_customer(customer, summaries.get(str(customer.id))) for customer in customers],
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
    summaries = await _collect_customer_activity_summaries(db, [customer])
    payload = _serialize_customer(customer, summaries.get(str(customer.id)))
    payload["activity"] = await _collect_recent_customer_activity(db, customer)
    payload["notes"] = await _collect_customer_notes(db, customer)
    payload["audit_history"] = await _collect_customer_audit_history(db, customer)
    return payload


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
    summaries = await _collect_customer_activity_summaries(db, customers)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "customers": [_serialize_customer(customer, summaries.get(str(customer.id))) for customer in customers],
    }

    if scope == "full":
        licences_result = await db.execute(select(Licence).order_by(Licence.created_at.desc()))
        scans_result = await db.execute(select(ScanHistory).order_by(ScanHistory.created_at.desc()))
        usage_result = await db.execute(select(UsageEvent).order_by(UsageEvent.created_at.desc()))
        comparisons_result = await db.execute(select(Comparison).order_by(Comparison.created_at.desc()))
        notes_result = await db.execute(select(CustomerNote).order_by(CustomerNote.created_at.desc()))
        audit_result = await db.execute(select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()))
        payload.update({
            "licences": [_serialize_licence(item) for item in licences_result.scalars().all()],
            "scans": [_serialize_scan(item) for item in scans_result.scalars().all()],
            "usage_events": [_serialize_usage_event(item) for item in usage_result.scalars().all()],
            "comparisons": [_serialize_comparison(item) for item in comparisons_result.scalars().all()],
            "customer_notes": [_serialize_customer_note(item) for item in notes_result.scalars().all()],
            "admin_audit_log": [_serialize_audit_event(item) for item in audit_result.scalars().all()],
        })

    return payload


@router.get("/customer/notes")
async def list_customer_notes(
    email: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, email)
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    return {
        "email": customer.email,
        "notes": await _collect_customer_notes(db, customer, limit=50),
    }


@router.post("/customer/notes", status_code=status.HTTP_201_CREATED)
async def add_customer_note(
    body: CustomerNoteRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    note = CustomerNote(
        customer_id=customer.id,
        author=_admin_actor(x_admin_actor),
        note=body.note.strip(),
    )
    db.add(note)
    await record_admin_audit_event(
        db,
        action="customer.note_added",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        details={"note_preview": body.note.strip()[:200]},
    )
    await db.commit()
    await db.refresh(note)
    return _serialize_customer_note(note)


@router.get("/audit")
async def list_audit_events(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    email: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(limit)
    if email:
        query = query.where(AdminAuditLog.customer_email == email)
    if action:
        query = query.where(AdminAuditLog.action == action)
    query = _apply_date_range(
        query,
        AdminAuditLog.created_at,
        date_from=_parse_date_filter(date_from),
        date_to=_parse_date_filter(date_to, inclusive_end=True),
    )
    result = await db.execute(query)
    events = result.scalars().all()
    return {
        "count": len(events),
        "events": [_serialize_audit_event(item) for item in events],
    }


@router.get("/metrics/summary")
async def metrics_summary(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    plan: str | None = Query(default=None, pattern="^(free|trial|developer|team|enterprise)$"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    start = _parse_date_filter(date_from)
    end = _parse_date_filter(date_to, inclusive_end=True)
    return {
        "date_from": start.isoformat() if start else None,
        "date_to": end.isoformat() if end else None,
        "plan": plan,
        "summary": await _metrics_summary(db, date_from=start, date_to=end, plan=plan),
    }


@router.get("/metrics/funnel")
async def metrics_funnel(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    plan: str | None = Query(default=None, pattern="^(free|trial|developer|team|enterprise)$"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    start = _parse_date_filter(date_from)
    end = _parse_date_filter(date_to, inclusive_end=True)
    return {
        "date_from": start.isoformat() if start else None,
        "date_to": end.isoformat() if end else None,
        "plan": plan,
        "funnel": await _metrics_funnel(db, date_from=start, date_to=end, plan=plan),
    }


@router.get("/metrics/usage")
async def metrics_usage(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    plan: str | None = Query(default=None, pattern="^(free|trial|developer|team|enterprise)$"),
    group_by: str = Query(default="plan", pattern="^(overall|plan|customer)$"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    start = _parse_date_filter(date_from)
    end = _parse_date_filter(date_to, inclusive_end=True)
    return {
        "date_from": start.isoformat() if start else None,
        "date_to": end.isoformat() if end else None,
        "plan": plan,
        "group_by": group_by,
        "usage": await _metrics_usage(db, date_from=start, date_to=end, plan=plan, group_by=group_by),
    }


@router.get("/metrics/export")
async def export_metrics(
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
    dataset: str = Query(pattern="^(customers|licences|usage_events|registration_funnel_events|scan_history|comparisons|customer_notes|admin_audit_log|metrics_summary|metrics_funnel|metrics_usage)$"),
    format: str = Query(default="json", pattern="^(json|csv)$"),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    plan: str | None = Query(default=None, pattern="^(free|trial|developer|team|enterprise)$"),
    group_by: str = Query(default="plan", pattern="^(overall|plan|customer)$"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    start = _parse_date_filter(date_from)
    end = _parse_date_filter(date_to, inclusive_end=True)

    if dataset == "metrics_summary":
        payload = [await _metrics_summary(db, date_from=start, date_to=end, plan=plan)]
    elif dataset == "metrics_funnel":
        payload = [await _metrics_funnel(db, date_from=start, date_to=end, plan=plan)]
    elif dataset == "metrics_usage":
        usage_payload = await _metrics_usage(db, date_from=start, date_to=end, plan=plan, group_by=group_by)
        payload = usage_payload["rows"] or [usage_payload["totals"]]
    else:
        query_map = {
            "customers": select(Customer).options(selectinload(Customer.licences)).order_by(Customer.created_at.desc()),
            "licences": select(Licence).order_by(Licence.created_at.desc()),
            "usage_events": select(UsageEvent).join(Licence, Licence.id == UsageEvent.licence_id).order_by(UsageEvent.created_at.desc()),
            "registration_funnel_events": select(RegistrationFunnelEvent).order_by(RegistrationFunnelEvent.created_at.desc()),
            "scan_history": select(ScanHistory).join(Licence, Licence.id == ScanHistory.licence_id).order_by(ScanHistory.created_at.desc()),
            "comparisons": select(Comparison).join(Licence, Licence.id == Comparison.licence_id).order_by(Comparison.created_at.desc()),
            "customer_notes": select(CustomerNote).join(Customer, Customer.id == CustomerNote.customer_id).order_by(CustomerNote.created_at.desc()),
            "admin_audit_log": select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()),
        }
        query = query_map[dataset]
        if dataset == "customers":
            query = _apply_date_range(query, Customer.created_at, date_from=start, date_to=end)
        elif dataset == "licences":
            query = _apply_date_range(query, Licence.created_at, date_from=start, date_to=end)
            if plan:
                query = query.where(Licence.plan == plan)
        elif dataset == "usage_events":
            query = _apply_date_range(query, UsageEvent.created_at, date_from=start, date_to=end)
            if plan:
                query = query.where(Licence.plan == plan)
        elif dataset == "registration_funnel_events":
            query = _apply_date_range(query, RegistrationFunnelEvent.created_at, date_from=start, date_to=end)
            if plan:
                query = query.where(RegistrationFunnelEvent.plan == plan)
        elif dataset == "scan_history":
            query = _apply_date_range(query, ScanHistory.created_at, date_from=start, date_to=end)
            if plan:
                query = query.where(Licence.plan == plan)
        elif dataset == "comparisons":
            query = _apply_date_range(query, Comparison.created_at, date_from=start, date_to=end)
            if plan:
                query = query.where(Licence.plan == plan)
        elif dataset == "customer_notes":
            query = _apply_date_range(query, CustomerNote.created_at, date_from=start, date_to=end)
        elif dataset == "admin_audit_log":
            query = _apply_date_range(query, AdminAuditLog.created_at, date_from=start, date_to=end)

        result = await db.execute(query)
        items = result.scalars().all()
        if dataset == "customers":
            summaries = await _collect_customer_activity_summaries(db, items)
            payload = [_serialize_customer(item, summaries.get(str(item.id))) for item in items]
        elif dataset == "licences":
            payload = [_serialize_licence(item) for item in items]
        elif dataset == "usage_events":
            payload = [_serialize_usage_event(item) for item in items]
        elif dataset == "registration_funnel_events":
            payload = [_serialize_registration_funnel_event(item) for item in items]
        elif dataset == "scan_history":
            payload = [_serialize_scan(item) for item in items]
        elif dataset == "comparisons":
            payload = [_serialize_comparison(item) for item in items]
        elif dataset == "customer_notes":
            payload = [_serialize_customer_note(item) for item in items]
        else:
            payload = [_serialize_audit_event(item) for item in items]

    await record_admin_audit_event(
        db,
        action="metrics.export",
        actor=_admin_actor(x_admin_actor),
        reason=f"{dataset}:{format}",
        details={
            "dataset": dataset,
            "format": format,
            "date_from": start.isoformat() if start else None,
            "date_to": end.isoformat() if end else None,
            "plan": plan,
            "group_by": group_by,
        },
    )
    await db.commit()

    if format == "csv":
        rows = payload if isinstance(payload, list) else [payload]
        return _csv_response(filename=f"owlvex-{dataset}.csv", rows=rows)
    return {
        "dataset": dataset,
        "format": format,
        "date_from": start.isoformat() if start else None,
        "date_to": end.isoformat() if end else None,
        "plan": plan,
        "group_by": group_by,
        "rows": payload,
    }


@router.post("/resend-verification")
async def resend_verification(
    body: ResendVerificationRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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
    await record_admin_audit_event(
        db,
        action="customer.resend_verification",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        details={"pending_plan": customer.pending_plan},
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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

    await record_admin_audit_event(
        db,
        action="customer.ban",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        reason=body.reason,
        details={"deactivated_licences": deactivated},
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    customer.is_banned = False
    customer.banned_at = None
    customer.ban_reason = None
    await record_admin_audit_event(
        db,
        action="customer.unban",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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

    await record_admin_audit_event(
        db,
        action="licence.deactivate",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        reason=body.plan,
        details={"deactivated": len(licences), "licence_ids": [str(licence.id) for licence in licences]},
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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
    current_settings = get_settings()
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
        expires_at=(
            None
            if source_licence.plan == "trial" and current_settings.environment == "development"
            else source_licence.expires_at
        ),
        is_active=True,
        stripe_customer_id=source_licence.stripe_customer_id,
        stripe_subscription_id=source_licence.stripe_subscription_id,
    )
    db.add(rotated)
    await record_admin_audit_event(
        db,
        action="licence.rotate",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        licence_id=str(source_licence.id),
        reason=body.plan,
        details={"rotated_from_licence_id": str(source_licence.id)},
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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

    await record_admin_audit_event(
        db,
        action="licence.telemetry",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        reason=body.plan,
        details={"telemetry_enabled": applied_enabled, "updated": updated},
    )
    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "plan": body.plan,
        "telemetry_enabled": applied_enabled,
        "updated": updated,
    }


@router.post("/licence/telemetry-profile")
async def update_licence_telemetry_profile(
    body: CustomerTelemetryProfileRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    _ensure_admin_key(x_admin_key)
    if body.profile == "dev_observability" and current_settings.environment != "development":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dev_observability telemetry profile is only available in development.",
        )

    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    licences = _filter_customer_licences(customer, body.plan)
    if not licences:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No licence found for this customer")

    updated = 0
    for licence in licences:
        features = dict(licence.features or {})
        features["telemetry_profile"] = body.profile
        licence.features = features
        updated += 1

    await record_admin_audit_event(
        db,
        action="licence.telemetry_profile",
        actor=_admin_actor(x_admin_actor),
        customer_id=str(customer.id),
        customer_email=customer.email,
        reason=body.plan,
        details={"telemetry_profile": body.profile, "updated": updated},
    )
    await db.commit()
    return {
        "ok": True,
        "email": customer.email,
        "plan": body.plan,
        "telemetry_profile": body.profile,
        "updated": updated,
    }


@router.post("/licence/delete")
async def delete_licence(
    body: DeleteLicenceRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
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
    customer_id = str(licence.customer_id) if licence.customer_id else None
    await record_admin_audit_event(
        db,
        action="licence.delete",
        actor=_admin_actor(x_admin_actor),
        customer_id=customer_id,
        customer_email=email,
        licence_id=licence_id,
    )
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
    x_admin_actor: str | None = Header(default=None, alias="X-Admin-Actor"),
    db: AsyncSession = Depends(get_db),
):
    _ensure_admin_key(x_admin_key)
    customer = await _get_customer_with_licences(db, str(body.email))
    if not customer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")

    deleted_licences = await _purge_customer_tree(db, customer)
    await record_admin_audit_event(
        db,
        action="customer.delete",
        actor=_admin_actor(x_admin_actor),
        customer_id=None,
        customer_email=customer.email,
        details={"deleted_licences": deleted_licences, "deleted_customer_id": str(customer.id)},
    )
    await db.commit()
    return {
        "ok": True,
        "email": str(body.email),
        "deleted": True,
        "deleted_licences": deleted_licences,
    }
