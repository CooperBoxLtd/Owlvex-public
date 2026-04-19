"""
Shared fixtures for the Owlvex backend test suite.

Uses an in-memory SQLite database (via aiosqlite) so tests run without
a real PostgreSQL instance.  The ARRAY and JSONB column types that
PostgreSQL provides are handled by overriding the dialect-specific types
with generic equivalents in the engine URL.
"""
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_KEY", "test-admin-key")

from app.main import app
from app.db.session import Base, get_db
from app.config import get_settings, Settings
from app.services.rate_limit import clear_rate_limit_state

# ---------------------------------------------------------------------------
# Override settings for tests
# ---------------------------------------------------------------------------
TEST_SETTINGS = Settings(
    database_url="sqlite+aiosqlite:///:memory:",
    secret_key="test-secret-key",
    admin_key="test-admin-key",
    stripe_secret_key="sk_test_fake",
    stripe_webhook_secret="whsec_test_fake",
    sendgrid_api_key="",
    environment="test",
)


@pytest.fixture(autouse=True)
def override_settings():
    app.dependency_overrides[get_settings] = lambda: TEST_SETTINGS
    clear_rate_limit_state()
    yield
    clear_rate_limit_state()
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# In-memory async database
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        # SQLite doesn't support ARRAY/JSONB natively — models use them via
        # PostgreSQL-specific types.  We create tables with a raw DDL approach
        # by importing models (which registers them on Base.metadata) and then
        # using a patched metadata creation.
        await conn.run_sync(_create_sqlite_tables)
    yield engine
    await engine.dispose()


def _create_sqlite_tables(conn):
    """Create simplified table schema compatible with SQLite for unit testing."""
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS frameworks (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            category TEXT,
            is_active INTEGER DEFAULT 1,
            plan_tier TEXT DEFAULT 'developer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            code TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            languages TEXT DEFAULT '[]',
            cwe_id TEXT,
            prompt_hints TEXT,
            fix_guidance TEXT,
            rule_references TEXT DEFAULT '[]',
            plan_tier TEXT DEFAULT 'developer',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS prompt_templates (
            id TEXT PRIMARY KEY,
            framework_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            language TEXT DEFAULT 'all',
            template TEXT NOT NULL,
            variables TEXT DEFAULT '[]',
            is_baseline INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            version INTEGER DEFAULT 1,
            plan_tier TEXT DEFAULT 'developer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT,
            company TEXT,
            source TEXT DEFAULT 'extension',
            pending_plan TEXT,
            email_verified_at TIMESTAMP,
            verification_code_hash TEXT,
            verification_code_expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS licences (
            id TEXT PRIMARY KEY,
            customer_id TEXT,
            licence_key_hash TEXT NOT NULL UNIQUE,
            team_name TEXT NOT NULL,
            email TEXT NOT NULL,
            plan TEXT NOT NULL,
            seats INTEGER DEFAULT 1,
            seats_used INTEGER DEFAULT 0,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            features TEXT DEFAULT '{}',
            industry_packs TEXT DEFAULT '[]',
            is_active INTEGER DEFAULT 1,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS licence_seats (
            id TEXT PRIMARY KEY,
            licence_id TEXT NOT NULL,
            user_email TEXT NOT NULL,
            user_name TEXT,
            is_admin INTEGER DEFAULT 0,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS team_prompts (
            id TEXT PRIMARY KEY,
            licence_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            system_prompt TEXT NOT NULL,
            frameworks TEXT DEFAULT '[]',
            model TEXT,
            temperature REAL DEFAULT 0.1,
            is_team_default INTEGER DEFAULT 0,
            created_by TEXT,
            parent_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            licence_id TEXT NOT NULL,
            user_email TEXT,
            file_hash TEXT,
            file_name TEXT,
            language TEXT,
            prompt_id TEXT,
            prompt_snapshot TEXT,
            model TEXT,
            provider TEXT,
            frameworks TEXT DEFAULT '[]',
            score REAL,
            finding_count INTEGER DEFAULT 0,
            findings_summary TEXT DEFAULT '{}',
            token_count INTEGER,
            duration_ms INTEGER,
            status TEXT DEFAULT 'completed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS comparisons (
            id TEXT PRIMARY KEY,
            licence_id TEXT NOT NULL,
            scan_a_id TEXT NOT NULL,
            scan_b_id TEXT NOT NULL,
            score_change REAL,
            new_findings INTEGER DEFAULT 0,
            resolved_findings INTEGER DEFAULT 0,
            diff_summary TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    conn.execute(__import__('sqlalchemy').text("""
        CREATE TABLE IF NOT EXISTS usage_events (
            id TEXT PRIMARY KEY,
            licence_id TEXT NOT NULL,
            user_email TEXT,
            event_name TEXT NOT NULL,
            metadata TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))


@pytest_asyncio.fixture
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
    app.dependency_overrides.pop(get_db, None)
