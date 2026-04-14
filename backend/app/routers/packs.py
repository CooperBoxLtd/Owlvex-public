from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.licence_service import validate_licence
from app.services.pack_service import get_pack_artifact, list_available_packs

router = APIRouter(prefix="/v1/packs", tags=["packs"])


@router.get("/manifest")
async def manifest(
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    return {
        "schema_version": "owlvex.rulepack.manifest-list.v1",
        "packs": list_available_packs(lic["features"]["frameworks"]),
    }


@router.get("/{pack_id}")
async def get_pack(
    pack_id: str,
    x_licence_key: str = Header(..., alias="X-Licence-Key"),
    db: AsyncSession = Depends(get_db),
):
    lic = await validate_licence(db, x_licence_key)
    if not lic["valid"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=lic["reason"])

    artifact = get_pack_artifact(pack_id, lic["features"]["frameworks"])
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pack not found or not permitted for this licence")

    return artifact
