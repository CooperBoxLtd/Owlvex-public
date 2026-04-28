from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.services.licence_service import is_telemetry_enabled, validate_licence
from app.services.rate_limit import allow_control_plane_request
from app.services.usage_service import record_usage_event

router = APIRouter(prefix="/v1/usage", tags=["usage"])

DEV_OBSERVABILITY_PROFILE = "dev_observability"

COMMON_USAGE_METADATA_FIELDS = {
    "provider",
    "model",
    "project_id",
    "project_mode",
    "project_configured",
}

DEV_OBSERVABILITY_METADATA_FIELDS = COMMON_USAGE_METADATA_FIELDS | {
    "telemetry_profile",
    "scope",
    "status",
    "stage",
    "error_kind",
    "agent_mode",
    "analysis_mix",
    "file_count",
    "finding_count",
    "risk_score",
    "risk_before",
    "risk_after",
    "target_removed",
    "duration_ms",
    "report_variant",
    "target_label",
    "warning_count",
    "average_score",
    "canonical_id",
    "severity",
    "outcome",
    "queue_ms",
    "read_files_ms",
    "deterministic_ms",
    "ai_review_ms",
    "verifier_ms",
    "skeptic_ms",
    "safe_probe_ms",
    "caller_path_ms",
    "report_ms",
    "fix_preview_ms",
    "post_fix_verify_ms",
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
    "fix_preview_generated": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "finding_count", "canonical_id", "severity"},
    "fix_preview_applied": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "canonical_id", "severity"},
    "fix_preview_discarded": COMMON_USAGE_METADATA_FIELDS | {"file_count", "canonical_id", "severity"},
    "fix_verification_completed": COMMON_USAGE_METADATA_FIELDS | {"outcome", "file_count", "canonical_id", "severity", "risk_before", "risk_after", "target_removed"},
}

DEV_OBSERVABILITY_EVENT_METADATA_FIELDS = {
    "scan_started": DEV_OBSERVABILITY_METADATA_FIELDS,
    "scan_completed": DEV_OBSERVABILITY_METADATA_FIELDS,
    "scan_failed": DEV_OBSERVABILITY_METADATA_FIELDS,
    "report_created": DEV_OBSERVABILITY_METADATA_FIELDS,
    "report_failed": DEV_OBSERVABILITY_METADATA_FIELDS,
    "fix_preview_started": DEV_OBSERVABILITY_METADATA_FIELDS,
    "fix_preview_completed": DEV_OBSERVABILITY_METADATA_FIELDS,
    "fix_preview_failed": DEV_OBSERVABILITY_METADATA_FIELDS,
    "fix_applied": DEV_OBSERVABILITY_METADATA_FIELDS,
    "fix_discarded": DEV_OBSERVABILITY_METADATA_FIELDS,
    "post_fix_scan_completed": DEV_OBSERVABILITY_METADATA_FIELDS,
}


def _resolve_allowed_usage_fields(event_name: str, metadata: dict, features: dict | None, environment: str) -> set[str]:
    if metadata.get("telemetry_profile") == DEV_OBSERVABILITY_PROFILE and environment != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="dev_observability telemetry is only accepted by the development backend.",
        )

    dev_fields = DEV_OBSERVABILITY_EVENT_METADATA_FIELDS.get(event_name)
    if dev_fields is not None:
        profile = (features or {}).get("telemetry_profile", "standard")
        if environment != "development" or profile != DEV_OBSERVABILITY_PROFILE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This usage event requires a dev_observability telemetry profile.",
            )
        return dev_fields

    allowed_fields = USAGE_EVENT_METADATA_FIELDS.get(event_name)
    if not allowed_fields:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported usage event '{event_name}'.",
        )
    return allowed_fields


def _sanitize_usage_metadata(event_name: str, metadata: dict, features: dict | None, environment: str) -> dict:
    allowed_fields = _resolve_allowed_usage_fields(event_name, metadata, features, environment)

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

    sanitized_metadata = _sanitize_usage_metadata(
        body.event_name,
        body.metadata,
        result.get("features"),
        settings.environment,
    )

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
