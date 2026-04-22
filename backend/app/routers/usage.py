from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.services.licence_service import is_telemetry_enabled, validate_licence
from app.services.rate_limit import allow_control_plane_request
from app.services.usage_service import record_usage_event

router = APIRouter(prefix="/v1/usage", tags=["usage"])

COMMON_USAGE_METADATA_FIELDS = {
    "provider",
    "model",
    "project_id",
    "project_mode",
    "project_configured",
}

USAGE_EVENT_METADATA_FIELDS = {
    "scan_run": COMMON_USAGE_METADATA_FIELDS | {"scope", "file_count", "finding_count"},
    "finding_viewed": COMMON_USAGE_METADATA_FIELDS | {"rule_code", "canonical_id", "severity", "scan_tier"},
    "fix_viewed": COMMON_USAGE_METADATA_FIELDS | {"rule_code", "canonical_id", "severity", "scan_tier"},
    "second_scan": COMMON_USAGE_METADATA_FIELDS | {"scope"},
    "session_return": COMMON_USAGE_METADATA_FIELDS | {"previous_session_at"},
    "limit_hit": COMMON_USAGE_METADATA_FIELDS | {"plan", "scans_this_month", "scans_remaining", "scans_per_month"},
    "feedback_positive": COMMON_USAGE_METADATA_FIELDS | {"scope", "file_count", "finding_count"},
    "feedback_negative": COMMON_USAGE_METADATA_FIELDS | {"scope", "file_count", "finding_count"},
    "registration_verified": COMMON_USAGE_METADATA_FIELDS | {"plan", "delivery", "has_project_root"},
    "project_root_selected": COMMON_USAGE_METADATA_FIELDS,
    "llm_provider_selected": COMMON_USAGE_METADATA_FIELDS | {"previous_provider"},
    "llm_model_selected": COMMON_USAGE_METADATA_FIELDS | {"previous_model"},
    "llm_connection_configured": COMMON_USAGE_METADATA_FIELDS | {"connection_result", "latency_ms"},
    "fix_preview_generated": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "canonical_id", "severity"},
    "fix_preview_applied": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "canonical_id", "severity"},
    "fix_preview_discarded": COMMON_USAGE_METADATA_FIELDS | {"file_count", "canonical_id", "severity"},
    "fix_verification_completed": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "canonical_id", "severity", "risk_before", "risk_after", "target_removed"},
}


def _sanitize_usage_metadata(event_name: str, metadata: dict) -> dict:
    allowed_fields = USAGE_EVENT_METADATA_FIELDS.get(event_name)
    if not allowed_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported usage event '{event_name}'.",
        )

    unknown_fields = sorted(set(metadata.keys()) - allowed_fields)
    if unknown_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported metadata fields for {event_name}: {', '.join(unknown_fields)}",
        )

    sanitized: dict = {}
    for key, value in metadata.items():
        if value is None or isinstance(value, (str, int, float, bool)):
            sanitized[key] = value
            continue

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Metadata field '{key}' must be a scalar JSON value.",
        )

    return sanitized


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

    if not is_telemetry_enabled(result.get("features")):
        return {
            "ok": True,
            "event_id": None,
            "event_name": body.event_name,
            "licence_id": result["licence_id"],
            "telemetry_disabled": True,
        }

    sanitized_metadata = _sanitize_usage_metadata(body.event_name, body.metadata)

    event = await record_usage_event(
        db,
        licence_id=result["licence_id"],
        user_email=body.user_email,
        event_name=body.event_name,
        metadata=sanitized_metadata,
    )
    return {
        "ok": True,
        "event_id": str(event.id),
        "event_name": event.event_name,
        "licence_id": result["licence_id"],
        "telemetry_disabled": False,
    }
