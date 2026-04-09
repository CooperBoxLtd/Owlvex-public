import hashlib
import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.db.models import Licence
from app.services.licence_service import (
    validate_licence,
    generate_licence_key,
    hash_licence_key,
    record_seat_seen,
)
from app.config import get_settings

router = APIRouter(prefix="/v1/licences", tags=["licences"])
settings = get_settings()


# ----------------------------------------------------------------
# POST /v1/licences/validate
# Called by VS Code extension on startup
# ----------------------------------------------------------------
class ValidateRequest(BaseModel):
    user_email: Optional[str] = None


@router.post("/validate")
async def validate(
    body: ValidateRequest,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    result = await validate_licence(db, x_licence_key)

    if not result["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=result["reason"])

    if body.user_email:
        await record_seat_seen(db, result["licence_id"], body.user_email)

    return result


# ----------------------------------------------------------------
# POST /v1/licences/generate
# Admin-only — creates a new licence (called after Stripe checkout)
# ----------------------------------------------------------------
class GenerateRequest(BaseModel):
    team_name: str
    email: EmailStr
    plan: str
    seats: int = 1
    expires_at: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None


PLAN_FEATURES = {
    "free": {
        "frameworks": ["OWASP"],
        "scans_per_day": 3,
        "prompt_editor": False,
        "comparison": False,
        "team_prompts": False,
        "ci_cd": False,
        "pdf_reports": False,
        "custom_rules": False,
        "sso": False,
    },
    "developer": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE"],
        "scans_per_day": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": False,
        "ci_cd": False,
        "pdf_reports": False,
        "custom_rules": False,
        "sso": False,
    },
    "team": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS"],
        "scans_per_day": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": True,
        "ci_cd": True,
        "pdf_reports": True,
        "custom_rules": False,
        "sso": False,
    },
    "enterprise": {
        "frameworks": ["OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS", "HIPAA"],
        "scans_per_day": None,
        "prompt_editor": True,
        "comparison": True,
        "team_prompts": True,
        "ci_cd": True,
        "pdf_reports": True,
        "custom_rules": True,
        "sso": True,
    },
}


@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate(
    body: GenerateRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key"),
    db: AsyncSession = Depends(get_db),
):
    if x_admin_key != settings.admin_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin key")

    if body.plan not in PLAN_FEATURES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown plan: {body.plan}")

    raw_key = generate_licence_key()
    key_hash = hash_licence_key(raw_key)

    expires_dt = None
    if body.expires_at:
        try:
            expires_dt = datetime.fromisoformat(body.expires_at)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            if expires_dt <= datetime.now(timezone.utc):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be a valid ISO 8601 datetime")

    licence = Licence(
        licence_key_hash=key_hash,
        team_name=body.team_name,
        email=body.email,
        plan=body.plan,
        seats=body.seats,
        features=PLAN_FEATURES[body.plan],
        stripe_customer_id=body.stripe_customer_id,
        stripe_subscription_id=body.stripe_subscription_id,
        expires_at=expires_dt,
    )
    db.add(licence)
    await db.commit()
    await db.refresh(licence)

    return {
        "licence_id": str(licence.id),
        "licence_key": raw_key,   # returned ONCE — never retrievable again
        "plan": licence.plan,
        "team_name": licence.team_name,
        "email": licence.email,
    }
