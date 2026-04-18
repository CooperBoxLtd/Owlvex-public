from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.prompt_builder import build_prompt
from app.services.rate_limit import rate_limiter
from app.config import get_settings

router = APIRouter(prefix="/v1/prompts", tags=["prompts"])
settings = get_settings()


class BuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frameworks: list[str] = ["OWASP"]
    language: str = "unknown"
    model: str = "gpt-4o"
    severity_threshold: str = "MEDIUM"
    custom_prompt: Optional[str] = None
    template_id: Optional[str] = None


@router.post("/build")
async def build(
    body: BuildRequest,
    request: Request,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    if not rate_limiter.allow("prompt_build", client_ip, settings.prompt_build_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many prompt build requests")

    # Validate licence and extract allowed frameworks
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    allowed = lic["features"]["frameworks"]

    result = await build_prompt(
        db=db,
        frameworks=body.frameworks,
        language=body.language,
        model=body.model,
        severity_threshold=body.severity_threshold,
        custom_prompt=body.custom_prompt,
        template_id=body.template_id,
        allowed_frameworks=allowed,
    )
    return result
