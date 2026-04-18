from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.prompt_builder import build_prompt

router = APIRouter(prefix="/v1/prompts", tags=["prompts"])


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
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
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
