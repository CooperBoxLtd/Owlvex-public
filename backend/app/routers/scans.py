from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
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
class FindingsSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)


class RecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file_name: str                          # filename only, no path
    file_hash: str                          # SHA256 of the scanned code
    language: str
    model: str
    provider: str
    frameworks: list[str]
    score: float
    findings_summary: FindingsSummary
    finding_count: int
    token_count: Optional[int] = None
    duration_ms: Optional[int] = None
    prompt_id: Optional[str] = None
    user_email: Optional[str] = None


class CompareFindingEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issue_id: Optional[str] = None
    canonical_title: Optional[str] = None
    title: Optional[str] = None
    line: Optional[int] = None
    framework: Optional[str] = None
    rule_code: Optional[str] = None
    severity: Optional[str] = None


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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=lic["reason"])

    quota_ok = await check_scan_quota(
        db,
        lic["licence_id"],
        lic["features"].get("scans_per_month", lic["features"].get("scans_per_day")),
    )
    if not quota_ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Monthly scan quota exceeded for this licence",
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
        findings_summary=body.findings_summary.model_dump(),
        finding_count=body.finding_count,
        token_count=body.token_count,
        duration_ms=body.duration_ms,
        prompt_id=body.prompt_id,
        user_email=body.user_email,
    )

    return {"scan_id": str(scan.id), "recorded": True}


# ----------------------------------------------------------------
# POST /v1/scans/compare
# Diff engine: findings sent from plugin memory, not from our DB
# ----------------------------------------------------------------
class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_a_id: str
    scan_b_id: str
    findings_a: list[CompareFindingEntry]
    findings_b: list[CompareFindingEntry]
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=lic["reason"])

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
        findings_a=[item.model_dump(exclude_none=True) for item in body.findings_a],
        findings_b=[item.model_dump(exclude_none=True) for item in body.findings_b],
        score_a=body.score_a,
        score_b=body.score_b,
    )
    return result
