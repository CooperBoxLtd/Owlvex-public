import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import AdminAuditLog


async def record_admin_audit_event(
    db: AsyncSession,
    *,
    action: str,
    actor: str | None,
    customer_id: str | None = None,
    licence_id: str | None = None,
    customer_email: str | None = None,
    reason: str | None = None,
    details: dict | None = None,
) -> AdminAuditLog:
    settings = get_settings()
    event = AdminAuditLog(
        customer_id=uuid.UUID(customer_id) if customer_id else None,
        licence_id=uuid.UUID(licence_id) if licence_id else None,
        customer_email=customer_email,
        actor=actor,
        action=action,
        reason=reason,
        environment=settings.environment,
        details=details or {},
    )
    db.add(event)
    await db.flush()
    return event
