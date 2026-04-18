from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.policy_engine import evaluate_policy

router = APIRouter(prefix="/v1/policies", tags=["policies"])


class PolicyFindingEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issue_id: Optional[str] = None
    canonical_id: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    line: Optional[int] = None


class PolicyConditions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issue_ids: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    minimum_severity: Optional[str] = None


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str = "warn"
    conditions: PolicyConditions = Field(default_factory=PolicyConditions)


class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[PolicyFindingEntry]
    policy: PolicyDefinition


@router.post("/evaluate")
async def evaluate(
    body: PolicyRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    return evaluate_policy(
        [item.model_dump(exclude_none=True) for item in body.findings],
        body.policy.model_dump(exclude_none=True),
    )
