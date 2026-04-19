from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import UsageEvent


async def record_usage_event(
    db: AsyncSession,
    *,
    licence_id: str,
    event_name: str,
    user_email: str | None = None,
    metadata: dict | None = None,
) -> UsageEvent:
    event = UsageEvent(
        licence_id=licence_id,
        user_email=user_email,
        event_name=event_name,
        event_data=metadata or {},
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event
