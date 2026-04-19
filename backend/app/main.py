import logging
import logging.config
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.session import engine, check_db_connection
from app.routers import health, licences, prompts, scans, billing, policies, packs, usage

settings = get_settings()

# ----------------------------------------------------------------
# Structured JSON logging
# ----------------------------------------------------------------
logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
        }
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        }
    },
    "root": {"handlers": ["stdout"], "level": "INFO"},
})

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Lifespan: startup checks
# ----------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting Owlvex API — environment={settings.environment}")

    db_ok = await check_db_connection()
    if not db_ok:
        logger.error("FATAL: Cannot connect to PostgreSQL on startup")
        raise RuntimeError("Database unreachable")

    logger.info("Database connection: OK")
    yield

    await engine.dispose()
    logger.info("Owlvex API shutdown complete")


# ----------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------
app = FastAPI(
    title="Owlvex API",
    description="AI-powered code security scanner backend",
    version="1.0.0",
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.is_development else [],
    allow_origin_regex=r"^vscode-webview://.*$" if not settings.is_development else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------
# Routes
# ----------------------------------------------------------------
app.include_router(health.router)
app.include_router(licences.router)
app.include_router(prompts.router)
app.include_router(scans.router)
app.include_router(policies.router)
app.include_router(billing.router)
app.include_router(packs.router)
app.include_router(usage.router)
