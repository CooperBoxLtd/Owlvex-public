from fastapi import APIRouter
from app.db.session import check_db_connection
from app.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health")
async def health():
    db_ok = await check_db_connection()

    return {
        "status": "ok" if db_ok else "degraded",
        "db": "ok" if db_ok else "error",
        "environment": settings.environment,
    }
