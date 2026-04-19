from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.rate_limit import allow_control_plane_request
from app.services.usage_service import record_usage_event

router = APIRouter(prefix="/v1/usage", tags=["usage"])


class UsageEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_name: str = Field(min_length=1, max_length=80)
    user_email: str | None = None
    metadata: dict = Field(default_factory=dict)


@router.post("/events", status_code=status.HTTP_201_CREATED)
async def create_usage_event(
    body: UsageEventRequest,
    request: Request,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    if not allow_control_plane_request(
        "usage_events",
        request,
        limit=settings.usage_event_rate_limit,
        window_seconds=settings.rate_limit_window_seconds,
        licence_key=x_licence_key,
        trust_forwarded_for=settings.trust_forwarded_for,
    ):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many usage events")

    result = await validate_licence(db, x_licence_key)
    if not result["valid"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=result["reason"])

    event = await record_usage_event(
        db,
        licence_id=result["licence_id"],
        user_email=body.user_email,
        event_name=body.event_name,
        metadata=body.metadata,
    )
    return {
        "ok": True,
        "event_id": str(event.id),
        "event_name": event.event_name,
        "licence_id": result["licence_id"],
    }
