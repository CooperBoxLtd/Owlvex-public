from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.policy_engine import evaluate_policy

router = APIRouter(prefix="/v1/policies", tags=["policies"])


class PolicyRequest(BaseModel):
    findings: list[dict]
    policy: dict


@router.post("/evaluate")
async def evaluate(
    body: PolicyRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    return evaluate_policy(body.findings, body.policy)
