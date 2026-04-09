"""
Unit tests for licence_service — hashing, generation, validation.
These tests run entirely in-memory without a real database connection.
"""
import pytest
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.licence_service import (
    hash_licence_key,
    generate_licence_key,
    get_licence_by_key,
    validate_licence,
    record_seat_seen,
)


# ---------------------------------------------------------------------------
# hash_licence_key
# ---------------------------------------------------------------------------
class TestHashLicenceKey:
    def test_produces_sha256_hex(self):
        raw = "owlvex_lic_abc123"
        result = hash_licence_key(raw)
        expected = hashlib.sha256(raw.encode()).hexdigest()
        assert result == expected

    def test_output_is_64_chars(self):
        assert len(hash_licence_key("anything")) == 64

    def test_deterministic(self):
        assert hash_licence_key("same") == hash_licence_key("same")

    def test_different_inputs_produce_different_hashes(self):
        assert hash_licence_key("key_a") != hash_licence_key("key_b")


# ---------------------------------------------------------------------------
# generate_licence_key
# ---------------------------------------------------------------------------
class TestGenerateLicenceKey:
    def test_starts_with_prefix(self):
        key = generate_licence_key()
        assert key.startswith("owlvex_lic_")

    def test_total_length(self):
        key = generate_licence_key()
        # prefix (11) + 32 random chars
        assert len(key) == 43

    def test_keys_are_unique(self):
        keys = {generate_licence_key() for _ in range(100)}
        assert len(keys) == 100

    def test_only_alphanumeric_random_part(self):
        key = generate_licence_key()
        random_part = key[len("owlvex_lic_"):]
        assert random_part.isalnum()


# ---------------------------------------------------------------------------
# validate_licence
# ---------------------------------------------------------------------------
def _make_licence(**kwargs):
    """Build a mock Licence ORM object."""
    defaults = {
        "id": str(uuid.uuid4()),
        "is_active": True,
        "expires_at": None,
        "plan": "developer",
        "team_name": "Test Team",
        "seats": 5,
        "seats_used": 1,
        "industry_packs": [],
        "features": {
            "frameworks": ["OWASP", "STRIDE"],
            "scans_per_day": 50,
            "prompt_editor": False,
            "comparison": True,
            "team_prompts": False,
            "ci_cd": False,
            "pdf_reports": False,
            "custom_rules": False,
            "sso": False,
        },
    }
    defaults.update(kwargs)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


@pytest.mark.asyncio
async def test_validate_licence_not_found():
    db = AsyncMock()
    with patch("app.services.licence_service.get_licence_by_key", return_value=None):
        result = await validate_licence(db, "owlvex_lic_nonexistent")
    assert result["valid"] is False
    assert "not found" in result["reason"]


@pytest.mark.asyncio
async def test_validate_licence_inactive():
    db = AsyncMock()
    licence = _make_licence(is_active=False)
    with patch("app.services.licence_service.get_licence_by_key", return_value=licence):
        result = await validate_licence(db, "owlvex_lic_test")
    assert result["valid"] is False
    assert "inactive" in result["reason"]


@pytest.mark.asyncio
async def test_validate_licence_expired():
    db = AsyncMock()
    expired = datetime(2020, 1, 1, tzinfo=timezone.utc)
    licence = _make_licence(expires_at=expired)
    with patch("app.services.licence_service.get_licence_by_key", return_value=licence):
        result = await validate_licence(db, "owlvex_lic_test")
    assert result["valid"] is False
    assert "expired" in result["reason"]


@pytest.mark.asyncio
async def test_validate_licence_valid():
    db = AsyncMock()
    future = datetime.now(timezone.utc) + timedelta(days=365)
    licence = _make_licence(expires_at=future)
    with patch("app.services.licence_service.get_licence_by_key", return_value=licence):
        result = await validate_licence(db, "owlvex_lic_test")
    assert result["valid"] is True
    assert result["plan"] == "developer"
    assert "OWASP" in result["features"]["frameworks"]


@pytest.mark.asyncio
async def test_validate_licence_no_expiry_is_valid():
    db = AsyncMock()
    licence = _make_licence(expires_at=None)
    with patch("app.services.licence_service.get_licence_by_key", return_value=licence):
        result = await validate_licence(db, "owlvex_lic_test")
    assert result["valid"] is True


@pytest.mark.asyncio
async def test_validate_returns_all_feature_flags():
    db = AsyncMock()
    licence = _make_licence()
    with patch("app.services.licence_service.get_licence_by_key", return_value=licence):
        result = await validate_licence(db, "owlvex_lic_test")
    features = result["features"]
    for flag in ["prompt_editor", "comparison", "team_prompts", "ci_cd", "pdf_reports", "custom_rules", "sso"]:
        assert flag in features
