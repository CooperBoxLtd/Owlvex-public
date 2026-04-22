from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RegistrationFunnelEvent


async def record_registration_funnel_event(
    db: AsyncSession,
    *,
    email: str,
    plan: str,
    event_name: str,
    customer_id=None,
    delivery: str | None = None,
    metadata: dict | None = None,
) -> RegistrationFunnelEvent:
    event = RegistrationFunnelEvent(
        customer_id=customer_id,
        email=email,
        plan=plan,
        event_name=event_name,
        delivery=delivery,
        event_data=metadata or {},
    )
    db.add(event)
    await db.flush()
    return event
