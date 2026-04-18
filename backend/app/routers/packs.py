import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.pack_service import get_pack_artifact, get_pack_signing_posture, list_available_packs
from app.services.rate_limit import rate_limiter
from app.config import get_settings

router = APIRouter(prefix="/v1/packs", tags=["packs"])
logger = logging.getLogger(__name__)
settings = get_settings()


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _audit_pack_event(
    event: str,
    request: Request,
    licence: dict,
    **extra: object,
) -> None:
    payload = {
        "event": event,
        "client_ip": _client_ip(request),
        "licence_id": licence.get("licence_id"),
        "team_name": licence.get("team_name"),
        "plan": licence.get("plan"),
        "frameworks": licence.get("features", {}).get("frameworks", []),
        **extra,
    }
    logger.info("pack_audit %s", payload)


@router.get("/manifest")
async def manifest(
    request: Request,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    if not rate_limiter.allow("pack_fetch", _client_ip(request), settings.pack_fetch_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many pack requests")

    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    manifests = list_available_packs(lic["plan"], lic["features"]["frameworks"])
    signing_posture = get_pack_signing_posture()
    _audit_pack_event(
        "manifest_issued",
        request,
        lic,
        pack_ids=[manifest["pack_id"] for manifest in manifests],
        key_id=signing_posture["key_id"],
        using_dev_fallback=signing_posture["using_dev_fallback"],
    )

    return {
        "schema_version": "owlvex.rulepack.manifest-list.v1",
        "packs": manifests,
    }


@router.get("/{pack_id}")
async def get_pack(
    pack_id: str,
    request: Request,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    if not rate_limiter.allow("pack_fetch", _client_ip(request), settings.pack_fetch_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many pack requests")

    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    artifact = get_pack_artifact(pack_id, lic["plan"], lic["features"]["frameworks"])
    if artifact is None:
        _audit_pack_event(
            "artifact_denied",
            request,
            lic,
            pack_id=pack_id,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pack not found or not permitted for this licence")

    _audit_pack_event(
        "artifact_issued",
        request,
        lic,
        pack_id=pack_id,
        key_id=artifact.get("key_id"),
        pack_type=artifact.get("pack_type"),
        pack_version=artifact.get("pack_version"),
    )
    return artifact
