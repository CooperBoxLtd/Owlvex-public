from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.scan_recorder import record_scan, record_comparison, check_scan_quota

router = APIRouter(prefix="/v1/scans", tags=["scans"])


# ----------------------------------------------------------------
# POST /v1/scans/record
# Records metadata after the VS Code extension completes a scan.
# Code is NEVER sent here.
# ----------------------------------------------------------------
class RecordRequest(BaseModel):
    file_name: str                          # filename only, no path
    file_hash: str                          # SHA256 of the scanned code
    language: str
    model: str
    provider: str
    frameworks: list[str]
    score: float
    findings_summary: dict                  # {critical:int, high:int, medium:int, low:int}
    finding_count: int
    token_count: Optional[int] = None
    duration_ms: Optional[int] = None
    prompt_id: Optional[str] = None
    prompt_snapshot: Optional[str] = None
    user_email: Optional[str] = None


@router.post("/record")
async def record(
    body: RecordRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    if any(c in body.file_name for c in ('/', '\\', '..')):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="file_name must be a plain filename with no path components")

    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    quota_ok = await check_scan_quota(
        db, lic["licence_id"], lic["features"]["scans_per_day"]
    )
    if not quota_ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily scan quota exceeded for this licence",
        )

    scan = await record_scan(
        db=db,
        licence_id=lic["licence_id"],
        file_name=body.file_name,
        file_hash=body.file_hash,
        language=body.language,
        model=body.model,
        provider=body.provider,
        frameworks=body.frameworks,
        score=body.score,
        findings_summary=body.findings_summary,
        finding_count=body.finding_count,
        token_count=body.token_count,
        duration_ms=body.duration_ms,
        prompt_id=body.prompt_id,
        prompt_snapshot=body.prompt_snapshot,
        user_email=body.user_email,
    )

    return {"scan_id": str(scan.id), "recorded": True}


# ----------------------------------------------------------------
# POST /v1/scans/compare
# Diff engine: findings sent from plugin memory, not from our DB
# ----------------------------------------------------------------
class CompareRequest(BaseModel):
    scan_a_id: str
    scan_b_id: str
    findings_a: list[dict]
    findings_b: list[dict]
    score_a: float
    score_b: float


@router.post("/compare")
async def compare(
    body: CompareRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    if not lic["features"]["comparison"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scan comparison requires Developer plan or above",
        )

    result = await record_comparison(
        db=db,
        licence_id=lic["licence_id"],
        scan_a_id=body.scan_a_id,
        scan_b_id=body.scan_b_id,
        findings_a=body.findings_a,
        findings_b=body.findings_b,
        score_a=body.score_a,
        score_b=body.score_b,
    )
    return result
