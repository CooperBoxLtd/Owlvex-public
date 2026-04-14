from unittest.mock import patch

import pytest

from app.config import Settings, get_settings
from app.services import pack_service


def _clear_settings_cache():
    get_settings.cache_clear()


def test_pack_signing_requires_configured_key_outside_development():
    _clear_settings_cache()
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        environment="production",
        owlvex_pack_signing_private_key_pem="",
        owlvex_pack_signing_key_id="",
    )

    with patch("app.services.pack_service.get_settings", return_value=settings):
        with pytest.raises(RuntimeError, match="private key is required"):
            pack_service._get_signing_private_key_pem()

        with pytest.raises(RuntimeError, match="key id is required"):
            pack_service._get_signing_key_id()


def test_pack_signing_posture_reports_dev_fallback_in_development():
    _clear_settings_cache()
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        environment="development",
        owlvex_pack_signing_private_key_pem="",
        owlvex_pack_signing_key_id="",
    )

    with patch("app.services.pack_service.get_settings", return_value=settings):
        posture = pack_service.get_pack_signing_posture()

    assert posture["environment"] == "development"
    assert posture["using_dev_fallback"] is True
    assert posture["key_id"] == pack_service.DEFAULT_SIGNING_KEY_ID
