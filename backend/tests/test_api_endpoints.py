"""
Integration tests for the FastAPI endpoints using an in-memory database.
Covers the production extension/backend contract surfaces.
"""
import pytest
import uuid
from unittest.mock import patch, MagicMock
from sqlalchemy import text
from app.config import Settings


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_health_returns_ok(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# /v1/packs/manifest and /v1/packs/{pack_id}
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pack_manifest_requires_licence(client):
    response = await client.get("/v1/packs/manifest")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_pack_manifest_returns_entitled_packs(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence), \
         patch("app.routers.packs.logger") as mock_logger:
        response = await client.get(
            "/v1/packs/manifest",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == "owlvex.rulepack.manifest-list.v1"
    assert any(pack["pack_id"] == "owlvex.issue-pack.v1" for pack in data["packs"])
    assert any(pack["pack_id"] == "owlvex.remediation-pack.v1" for pack in data["packs"])
    assert any(pack["pack_id"] == "owlvex.framework-pack.2026.1" for pack in data["packs"])
    assert any(pack["pack_id"] == "owlvex.policy-pack.v1" for pack in data["packs"])
    assert any(pack["pack_id"] == "owlvex.stride.2026.1" for pack in data["packs"])
    assert all(pack["signature_algorithm"] == "ed25519" for pack in data["packs"])
    assert all(pack.get("signature") for pack in data["packs"])
    assert all(pack.get("key_id") for pack in data["packs"])
    assert all(pack["licence_scope"]["plan"] == "developer" for pack in data["packs"])
    assert all("OWASP" in pack["licence_scope"]["frameworks"] for pack in data["packs"])
    mock_logger.info.assert_called()


@pytest.mark.asyncio
async def test_pack_artifact_returns_metadata_only_payload(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence), \
         patch("app.routers.packs.logger") as mock_logger:
        response = await client.get(
            "/v1/packs/owlvex.issue-pack.v1",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == "owlvex.rulepack.artifact.v1"
    assert data["pack_id"] == "owlvex.issue-pack.v1"
    assert "artifact" in data
    assert "sha256" in data
    assert data["signature_algorithm"] == "ed25519"
    assert data["signature"]
    assert data["licence_scope"]["plan"] == "developer"
    assert data["artifact"]["schema_version"] == "owlvex.issue-pack.v1"
    mock_logger.info.assert_called()


@pytest.mark.asyncio
async def test_remediation_pack_artifact_is_available(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence):
        response = await client.get(
            "/v1/packs/owlvex.remediation-pack.v1",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["pack_id"] == "owlvex.remediation-pack.v1"
    assert data["artifact"]["schema_version"] == "owlvex.remediation-pack.v1"


@pytest.mark.asyncio
async def test_policy_pack_artifact_is_available(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence):
        response = await client.get(
            "/v1/packs/owlvex.policy-pack.v1",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["pack_id"] == "owlvex.policy-pack.v1"
    assert data["artifact"]["schema_version"] == "owlvex.policy-pack.v1"


@pytest.mark.asyncio
async def test_framework_pack_artifact_is_available(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence):
        response = await client.get(
            "/v1/packs/owlvex.framework-pack.2026.1",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["pack_id"] == "owlvex.framework-pack.2026.1"
    assert data["pack_type"] == "framework-pack"
    assert data["artifact"]["schema_version"] == "owlvex.framework-pack.v1"
    assert any(item["code"] == "OWASP" for item in data["artifact"]["frameworks"])


@pytest.mark.asyncio
async def test_pack_artifact_hides_unentitled_pack(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP"]},
    }

    with patch("app.routers.packs.validate_licence", return_value=mock_licence):
        response = await client.get(
            "/v1/packs/owlvex.stride.2026.1",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_pack_manifest_rate_limits_repeated_requests(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.settings.pack_fetch_rate_limit", 2), \
         patch("app.routers.packs.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.packs.validate_licence", return_value=mock_licence):
        for _ in range(2):
            response = await client.get(
                "/v1/packs/manifest",
                headers={"X-Licence-Key": "owlvex_lic_valid"},
            )
            assert response.status_code == 200

        response = await client.get(
            "/v1/packs/manifest",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
        )

    assert response.status_code == 429


@pytest.mark.asyncio
async def test_pack_manifest_does_not_trust_spoofed_forwarded_for_by_default(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "STRIDE"]},
    }

    with patch("app.routers.packs.settings.pack_fetch_rate_limit", 2), \
         patch("app.routers.packs.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.packs.settings.trust_forwarded_for", False), \
         patch("app.routers.packs.validate_licence", return_value=mock_licence):
        for forwarded_for in ("1.1.1.1", "2.2.2.2"):
            response = await client.get(
                "/v1/packs/manifest",
                headers={"X-Licence-Key": "owlvex_lic_valid", "X-Forwarded-For": forwarded_for},
            )
            assert response.status_code == 200

        response = await client.get(
            "/v1/packs/manifest",
            headers={"X-Licence-Key": "owlvex_lic_valid", "X-Forwarded-For": "3.3.3.3"},
        )

    assert response.status_code == 429


# ---------------------------------------------------------------------------
# /v1/licences/validate
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_validate_licence_missing_header(client):
    response = await client.post("/v1/licences/validate")
    assert response.status_code == 422  # FastAPI validation error — header required


@pytest.mark.asyncio
async def test_validate_licence_invalid_key(client):
    with patch("app.routers.licences.validate_licence", return_value={"valid": False, "reason": "Licence key not found"}):
        response = await client.post(
            "/v1/licences/validate",
            headers={"X-Licence-Key": "owlvex_lic_invalid"},
        )
    assert response.status_code == 401
    assert "not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_validate_licence_valid_key(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "team",
        "seats": 5,
        "seats_used": 1,
        "features": {
            "frameworks": ["OWASP", "STRIDE", "CWE"],
            "scans_per_day": 100,
            "prompt_editor": True,
            "comparison": True,
            "team_prompts": True,
            "ci_cd": False,
            "pdf_reports": False,
            "custom_rules": False,
            "sso": False,
            "industry_packs": [],
        },
        "usage": {
            "scans_today": 0,
            "scans_remaining": 100,
            "daily_limit_reached": False,
        },
        "expires_at": None,
    }
    with patch("app.routers.licences.validate_licence", return_value=mock_result):
        response = await client.post(
            "/v1/licences/validate",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["plan"] == "team"
    assert data["team_name"] == "Test Corp"
    assert "OWASP" in data["features"]["frameworks"]
    assert data["usage"]["daily_limit_reached"] is False


@pytest.mark.asyncio
async def test_validate_licence_rejects_unexpected_fields(client):
    with patch("app.routers.licences.validate_licence", return_value={"valid": True, "licence_id": str(uuid.uuid4()), "features": {"frameworks": ["OWASP"]}}):
        response = await client.post(
            "/v1/licences/validate",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"user_email": "user@example.com", "source_code": "should not be accepted"},
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_validate_licence_rate_limits_repeated_requests(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "team",
        "seats": 5,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": 100},
        "usage": {"scans_today": 0, "scans_remaining": 100, "daily_limit_reached": False},
        "expires_at": None,
    }
    with patch("app.routers.licences.settings.licence_validate_rate_limit", 2), \
         patch("app.routers.licences.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.licences.validate_licence", return_value=mock_result):
        for _ in range(2):
            response = await client.post(
                "/v1/licences/validate",
                headers={"X-Licence-Key": "owlvex_lic_validkey"},
                json={},
            )
            assert response.status_code == 200

        response = await client.post(
            "/v1/licences/validate",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={},
        )

    assert response.status_code == 429


@pytest.mark.asyncio
async def test_validate_licence_does_not_trust_spoofed_forwarded_for_by_default(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "team",
        "seats": 5,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": 100},
        "usage": {"scans_today": 0, "scans_remaining": 100, "daily_limit_reached": False},
        "expires_at": None,
    }
    with patch("app.routers.licences.settings.licence_validate_rate_limit", 2), \
         patch("app.routers.licences.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.licences.settings.trust_forwarded_for", False), \
         patch("app.routers.licences.validate_licence", return_value=mock_result):
        for forwarded_for in ("1.1.1.1", "2.2.2.2"):
            response = await client.post(
                "/v1/licences/validate",
                headers={"X-Licence-Key": "owlvex_lic_validkey", "X-Forwarded-For": forwarded_for},
                json={},
            )
            assert response.status_code == 200

        response = await client.post(
            "/v1/licences/validate",
            headers={"X-Licence-Key": "owlvex_lic_validkey", "X-Forwarded-For": "3.3.3.3"},
            json={},
        )

    assert response.status_code == 429


# ---------------------------------------------------------------------------
# /v1/licences/generate (admin)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_generate_licence_requires_admin_key(client):
    response = await client.post(
        "/v1/licences/generate",
        json={"team_name": "New Corp", "email": "admin@newcorp.com", "plan": "developer"},
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_generate_licence_valid(client):
    response = await client.post(
        "/v1/licences/generate",
        json={"team_name": "New Corp", "email": "admin@newcorp.com", "plan": "developer", "seats": 1},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["licence_key"].startswith("owlvex_lic_")
    assert data["plan"] == "developer"
    assert data["team_name"] == "New Corp"


@pytest.mark.asyncio
async def test_generate_licence_creates_customer_and_links_admin_issued_licence(client):
    response = await client.post(
        "/v1/licences/generate",
        json={"team_name": "Owlvex Team", "email": "team-admin@example.com", "plan": "team", "seats": 5},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 201

    overview = await client.get(
        "/v1/admin/overview",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert overview.status_code == 200
    customer = next(customer for customer in overview.json()["customers"] if customer["email"] == "team-admin@example.com")
    assert customer["source"] == "admin"
    assert customer["email_verified_at"] is not None
    assert customer["summary"]["active_licence_count"] == 1
    assert customer["summary"]["active_plan"] == "team"
    assert customer["licences"][0]["plan"] == "team"
    assert customer["licences"][0]["customer_id"] == customer["customer_id"]


@pytest.mark.asyncio
async def test_generate_licence_invalid_plan(client):
    response = await client.post(
        "/v1/licences/generate",
        json={"team_name": "X", "email": "x@x.com", "plan": "nonexistent"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_generate_licence_rejects_unexpected_fields(client):
    response = await client.post(
        "/v1/licences/generate",
        json={"team_name": "New Corp", "email": "admin@newcorp.com", "plan": "developer", "seats": 1, "prompt_snapshot": "nope"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_admin_overview_requires_admin_key(client):
    response = await client.get("/v1/admin/overview")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_admin_overview_returns_recent_customers(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "overview-user@example.com", "plan": "free"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]
    verification = await client.post(
        "/v1/licences/verify-email",
        json={"email": "overview-user@example.com", "code": verification_code},
    )
    assert verification.status_code == 201

    response = await client.get(
        "/v1/admin/overview",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 1
    customer = next(customer for customer in data["customers"] if customer["email"] == "overview-user@example.com")
    assert customer["summary"]["active_licence_count"] == 1
    assert customer["summary"]["active_plan"] == "free"
    assert customer["summary"]["verification_pending"] is False


@pytest.mark.asyncio
async def test_admin_customer_lookup_returns_licence_state(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "lookup-user@example.com", "plan": "trial", "name": "Lookup User"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]
    verification = await client.post(
        "/v1/licences/verify-email",
        json={"email": "lookup-user@example.com", "code": verification_code},
    )
    assert verification.status_code == 201

    response = await client.get(
        "/v1/admin/customer",
        params={"email": "lookup-user@example.com"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "lookup-user@example.com"
    assert data["email_verified_at"] is not None
    assert data["licences"][0]["plan"] == "trial"
    assert data["summary"]["active_plan"] == "trial"
    assert data["activity"]["recent_scans"] == []
    assert data["activity"]["recent_usage_events"] == []
    assert data["activity"]["recent_comparisons"] == []


@pytest.mark.asyncio
async def test_admin_resend_verification_returns_new_code(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "pending-user@example.com", "plan": "free"},
    )
    assert registration.status_code == 201

    response = await client.post(
        "/v1/admin/resend-verification",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "pending-user@example.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["email"] == "pending-user@example.com"
    assert isinstance(data.get("verification_code"), str)


@pytest.mark.asyncio
async def test_admin_deactivate_licence_marks_active_licence_inactive(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "deactivate-user@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "deactivate-user@example.com", "code": verification_code},
    )

    response = await client.post(
        "/v1/admin/licence/deactivate",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "deactivate-user@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["deactivated"] == 1


@pytest.mark.asyncio
async def test_admin_rotate_licence_issues_new_key(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "rotate-user@example.com", "plan": "trial"},
    )
    verification_code = registration.json()["verification_code"]
    verified = await client.post(
        "/v1/licences/verify-email",
        json={"email": "rotate-user@example.com", "code": verification_code},
    )
    old_key = verified.json()["licence_key"]

    response = await client.post(
        "/v1/admin/licence/rotate",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "rotate-user@example.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["licence_key"].startswith("owlvex_lic_")
    assert data["licence_key"] != old_key


@pytest.mark.asyncio
async def test_development_admin_rotate_clears_trial_expiry(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "rotate-dev-trial@example.com", "plan": "trial"},
    )
    verification_code = registration.json()["verification_code"]
    verified = await client.post(
        "/v1/licences/verify-email",
        json={"email": "rotate-dev-trial@example.com", "code": verification_code},
    )
    assert verified.status_code == 201
    assert verified.json()["expires_at"] is not None

    development_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="",
        environment="development",
    )
    with patch("app.routers.admin.get_settings", return_value=development_settings):
        response = await client.post(
            "/v1/admin/licence/rotate",
            headers={"X-Admin-Key": "test-admin-key"},
            json={"email": "rotate-dev-trial@example.com", "plan": "trial"},
        )

    assert response.status_code == 200

    customer = await client.get(
        "/v1/admin/customer",
        headers={"X-Admin-Key": "test-admin-key"},
        params={"email": "rotate-dev-trial@example.com"},
    )
    assert customer.status_code == 200
    active_trial = next(
        licence for licence in customer.json()["licences"]
        if licence["plan"] == "trial" and licence["is_active"]
    )
    assert active_trial["expires_at"] is None


@pytest.mark.asyncio
async def test_admin_app_route_serves_console(client):
    response = await client.get("/v1/admin/app")
    assert response.status_code == 200
    assert "Owlvex Admin Console" in response.text


@pytest.mark.asyncio
async def test_admin_export_returns_full_snapshot(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "export-user@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "export-user@example.com", "code": verification_code},
    )

    response = await client.get(
        "/v1/admin/export?scope=full",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scope"] == "full"
    assert any(customer["email"] == "export-user@example.com" for customer in data["customers"])
    assert "licences" in data
    assert "usage_events" in data
    assert "customer_notes" in data
    assert "admin_audit_log" in data


@pytest.mark.asyncio
async def test_admin_ban_customer_deactivates_licences_and_blocks_validation(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "ban-user@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    verified = await client.post(
        "/v1/licences/verify-email",
        json={"email": "ban-user@example.com", "code": verification_code},
    )
    licence_key = verified.json()["licence_key"]

    response = await client.post(
        "/v1/admin/customer/ban",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "ban-user@example.com", "reason": "abuse"},
    )
    assert response.status_code == 200
    assert response.json()["is_banned"] is True

    validate_response = await client.post(
        "/v1/licences/validate",
        headers={"X-Licence-Key": licence_key},
        json={},
    )
    assert validate_response.status_code == 401

    second_registration = await client.post(
        "/v1/licences/register",
        json={"email": "ban-user@example.com", "plan": "free"},
    )
    assert second_registration.status_code == 403


@pytest.mark.asyncio
async def test_admin_delete_licence_removes_it(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "delete-licence@example.com", "plan": "trial"},
    )
    verification_code = registration.json()["verification_code"]
    verified = await client.post(
        "/v1/licences/verify-email",
        json={"email": "delete-licence@example.com", "code": verification_code},
    )
    licence_id = verified.json()["licence_id"]
    licence_key = verified.json()["licence_key"]

    response = await client.post(
        "/v1/admin/licence/delete",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"licence_id": licence_id},
    )
    assert response.status_code == 200
    assert response.json()["deleted"] is True

    validate_response = await client.post(
        "/v1/licences/validate",
        headers={"X-Licence-Key": licence_key},
        json={},
    )
    assert validate_response.status_code == 401


@pytest.mark.asyncio
async def test_admin_delete_customer_purges_customer_tree(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "delete-customer@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "delete-customer@example.com", "code": verification_code},
    )

    response = await client.post(
        "/v1/admin/customer/delete",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "delete-customer@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["deleted"] is True

    lookup_response = await client.get(
        "/v1/admin/customer",
        params={"email": "delete-customer@example.com"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert lookup_response.status_code == 404


@pytest.mark.asyncio
async def test_admin_can_add_customer_note_and_lookup_returns_it(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "note-user@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "note-user@example.com", "code": verification_code},
    )

    note_response = await client.post(
        "/v1/admin/customer/notes",
        headers={"X-Admin-Key": "test-admin-key", "X-Admin-Actor": "ops@example.com"},
        json={"email": "note-user@example.com", "note": "Customer asked for onboarding follow-up."},
    )
    assert note_response.status_code == 201
    assert note_response.json()["author"] == "ops@example.com"

    lookup_response = await client.get(
        "/v1/admin/customer",
        params={"email": "note-user@example.com"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert lookup_response.status_code == 200
    data = lookup_response.json()
    assert data["notes"][0]["note"] == "Customer asked for onboarding follow-up."
    assert any(item["action"] == "customer.note_added" for item in data["audit_history"])


@pytest.mark.asyncio
async def test_admin_ban_writes_audit_log(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "audit-user@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "audit-user@example.com", "code": verification_code},
    )

    response = await client.post(
        "/v1/admin/customer/ban",
        headers={"X-Admin-Key": "test-admin-key", "X-Admin-Actor": "security@example.com"},
        json={"email": "audit-user@example.com", "reason": "abuse"},
    )
    assert response.status_code == 200

    audit_response = await client.get(
        "/v1/admin/audit",
        params={"email": "audit-user@example.com"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert audit_response.status_code == 200
    events = audit_response.json()["events"]
    assert any(item["action"] == "customer.ban" and item["actor"] == "security@example.com" for item in events)


@pytest.mark.asyncio
async def test_admin_metrics_summary_and_funnel_return_counts(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "metrics-user@example.com", "plan": "trial"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "metrics-user@example.com", "code": verification_code},
    )

    summary_response = await client.get(
        "/v1/admin/metrics/summary",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    funnel_response = await client.get(
        "/v1/admin/metrics/funnel",
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert summary_response.status_code == 200
    assert funnel_response.status_code == 200
    assert summary_response.json()["summary"]["licences_issued"] >= 1
    assert funnel_response.json()["funnel"]["registrations_started"] >= 1
    assert funnel_response.json()["funnel"]["verification_completed"] >= 1


@pytest.mark.asyncio
async def test_admin_metrics_export_csv_returns_downloadable_payload(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "export-metrics@example.com", "plan": "free"},
    )
    verification_code = registration.json()["verification_code"]
    await client.post(
        "/v1/licences/verify-email",
        json={"email": "export-metrics@example.com", "code": verification_code},
    )

    response = await client.get(
        "/v1/admin/metrics/export",
        params={"dataset": "customers", "format": "csv"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "email" in response.text


@pytest.mark.asyncio
async def test_admin_metrics_usage_supports_overall_plan_and_customer_grouping(client, db_session):
    for email, plan in (
        ("usage-trial@example.com", "trial"),
        ("usage-free@example.com", "free"),
    ):
        registration = await client.post(
            "/v1/licences/register",
            json={"email": email, "plan": plan},
        )
        code = registration.json()["verification_code"]
        verification = await client.post(
            "/v1/licences/verify-email",
            json={"email": email, "code": code},
        )
        assert verification.status_code == 201

    licence_rows = (
        await db_session.execute(text("SELECT id, customer_id, email, plan FROM licences ORDER BY email ASC"))
    ).all()
    assert len(licence_rows) == 2

    for licence_id, customer_id, email, plan in licence_rows:
        scan_a_id = str(uuid.uuid4())
        scan_b_id = str(uuid.uuid4())
        await db_session.execute(
            text(
                """
                INSERT INTO scan_history (
                    id, licence_id, user_email, file_hash, file_name, language, prompt_id,
                    model, provider, frameworks, score, finding_count, findings_summary,
                    token_count, duration_ms, status
                ) VALUES (
                    :id, :licence_id, :user_email, :file_hash, :file_name, :language, :prompt_id,
                    :model, :provider, :frameworks, :score, :finding_count, :findings_summary,
                    :token_count, :duration_ms, :status
                )
                """
            ),
            {
                "id": scan_a_id,
                "licence_id": str(licence_id),
                "user_email": email,
                "file_hash": "hash-a",
                "file_name": f"{plan}-a.py",
                "language": "python",
                "prompt_id": None,
                "model": "claude-sonnet-4",
                "provider": "anthropic",
                "frameworks": '["OWASP"]',
                "score": 7.0,
                "finding_count": 3,
                "findings_summary": "{}",
                "token_count": 120,
                "duration_ms": 450,
                "status": "completed",
            },
        )
        await db_session.execute(
            text(
                """
                INSERT INTO scan_history (
                    id, licence_id, user_email, file_hash, file_name, language, prompt_id,
                    model, provider, frameworks, score, finding_count, findings_summary,
                    token_count, duration_ms, status
                ) VALUES (
                    :id, :licence_id, :user_email, :file_hash, :file_name, :language, :prompt_id,
                    :model, :provider, :frameworks, :score, :finding_count, :findings_summary,
                    :token_count, :duration_ms, :status
                )
                """
            ),
            {
                "id": scan_b_id,
                "licence_id": str(licence_id),
                "user_email": email,
                "file_hash": "hash-b",
                "file_name": f"{plan}-b.py",
                "language": "python",
                "prompt_id": None,
                "model": "claude-sonnet-4",
                "provider": "anthropic",
                "frameworks": '["OWASP"]',
                "score": 8.0,
                "finding_count": 5,
                "findings_summary": "{}",
                "token_count": 180,
                "duration_ms": 520,
                "status": "completed",
            },
        )
        await db_session.execute(
            text(
                """
                INSERT INTO usage_events (id, licence_id, user_email, event_name, metadata)
                VALUES (:id, :licence_id, :user_email, :event_name, :metadata)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "licence_id": str(licence_id),
                "user_email": email,
                "event_name": "scan_run",
                "metadata": '{"scope":"workspace"}',
            },
        )
        await db_session.execute(
            text(
                """
                INSERT INTO comparisons (id, licence_id, scan_a_id, scan_b_id, score_change, new_findings, resolved_findings, diff_summary)
                VALUES (:id, :licence_id, :scan_a_id, :scan_b_id, :score_change, :new_findings, :resolved_findings, :diff_summary)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "licence_id": str(licence_id),
                "scan_a_id": scan_a_id,
                "scan_b_id": scan_b_id,
                "score_change": 1.0,
                "new_findings": 2,
                "resolved_findings": 1,
                "diff_summary": "{}",
            },
        )
    await db_session.commit()

    overall_response = await client.get(
        "/v1/admin/metrics/usage",
        params={"group_by": "overall"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    plan_response = await client.get(
        "/v1/admin/metrics/usage",
        params={"group_by": "plan"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    customer_response = await client.get(
        "/v1/admin/metrics/usage",
        params={"group_by": "customer"},
        headers={"X-Admin-Key": "test-admin-key"},
    )

    assert overall_response.status_code == 200
    assert plan_response.status_code == 200
    assert customer_response.status_code == 200

    overall_usage = overall_response.json()["usage"]
    assert overall_usage["group_by"] == "overall"
    assert len(overall_usage["rows"]) == 1
    assert overall_usage["totals"]["scans"] == 4
    assert overall_usage["totals"]["comparisons"] == 2
    assert overall_usage["totals"]["usage_events"] == 2

    plan_usage = plan_response.json()["usage"]
    assert plan_usage["group_by"] == "plan"
    assert {row["plan"] for row in plan_usage["rows"]} == {"free", "trial"}

    customer_usage = customer_response.json()["usage"]
    assert customer_usage["group_by"] == "customer"
    assert {row["customer"] for row in customer_usage["rows"]} == {"usage-free@example.com", "usage-trial@example.com"}

    export_response = await client.get(
        "/v1/admin/metrics/export",
        params={"dataset": "metrics_usage", "format": "json", "group_by": "customer"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert export_response.status_code == 200
    export_rows = export_response.json()["rows"]
    assert {row["customer"] for row in export_rows} == {"usage-free@example.com", "usage-trial@example.com"}


@pytest.mark.asyncio
async def test_register_free_licence_creates_tracked_access(client):
    response = await client.post(
        "/v1/licences/register",
        json={"email": "free-user@example.com", "plan": "free"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "verification_required"
    assert data["email"] == "free-user@example.com"
    assert data["plan"] == "free"
    assert data["delivery"] == "development_inline"
    assert isinstance(data.get("verification_code"), str)


@pytest.mark.asyncio
async def test_register_trial_licence_sets_expiry(client):
    response = await client.post(
        "/v1/licences/register",
        json={"email": "trial-user@example.com", "plan": "trial", "name": "Trial User"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "verification_required"
    assert data["plan"] == "trial"
    assert data["email"] == "trial-user@example.com"
    assert data["expires_in_minutes"] > 0


@pytest.mark.asyncio
async def test_registration_funnel_events_are_recorded_and_exportable(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "funnel-user@example.com", "plan": "free"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]

    verification = await client.post(
        "/v1/licences/verify-email",
        json={"email": "funnel-user@example.com", "code": verification_code},
    )
    assert verification.status_code == 201

    export_response = await client.get(
        "/v1/admin/metrics/export",
        params={"dataset": "registration_funnel_events", "format": "json"},
        headers={"X-Admin-Key": "test-admin-key"},
    )
    assert export_response.status_code == 200
    rows = export_response.json()["rows"]
    target_rows = [row for row in rows if row["email"] == "funnel-user@example.com"]
    event_names = {row["event_name"] for row in target_rows}
    assert {"registration_started", "verification_sent", "verification_completed", "licence_issued"} <= event_names


@pytest.mark.asyncio
async def test_register_licence_uses_email_delivery_when_resend_is_configured(client):
    configured_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="re_test",
        from_email="verified-sender@example.com",
        environment="production",
    )

    with patch("app.routers.licences.get_settings", return_value=configured_settings), \
         patch("app.routers.licences.send_verification_email") as mock_send_verification_email:
        response = await client.post(
            "/v1/licences/register",
            json={"email": "mail-user@example.com", "plan": "free"},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["delivery"] == "email"
    assert "verification_code" not in data
    mock_send_verification_email.assert_called_once()


@pytest.mark.asyncio
async def test_register_licence_surfaces_email_delivery_failure(client):
    configured_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="re_test",
        from_email="verified-sender@example.com",
        environment="production",
    )

    with patch("app.routers.licences.get_settings", return_value=configured_settings), \
         patch("app.routers.licences.send_verification_email", side_effect=RuntimeError("Email delivery failed with HTTP 403: validation_error: The from address does not match a verified domain.")):
        response = await client.post(
            "/v1/licences/register",
            json={"email": "mail-user@example.com", "plan": "free"},
        )

    assert response.status_code == 503
    assert "verified domain" in response.json()["detail"]


@pytest.mark.asyncio
async def test_register_licence_rejects_invalid_plan(client):
    response = await client.post(
        "/v1/licences/register",
        json={"email": "bad-plan@example.com", "plan": "developer"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_licence_rejects_unexpected_fields(client):
    response = await client.post(
        "/v1/licences/register",
        json={"email": "free-user@example.com", "plan": "free", "source_code": "nope"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_verify_email_registration_issues_licence(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "verify-user@example.com", "plan": "trial", "name": "Verify User"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]

    response = await client.post(
        "/v1/licences/verify-email",
        json={"email": "verify-user@example.com", "code": verification_code},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["licence_key"].startswith("owlvex_lic_")
    assert data["plan"] == "trial"
    assert data["team_name"] == "Verify User's Workspace"
    assert data["expires_at"] is not None


@pytest.mark.asyncio
async def test_development_trial_registration_has_no_expiry(client):
    development_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="",
        environment="development",
    )

    with patch("app.routers.licences.get_settings", return_value=development_settings):
        registration = await client.post(
            "/v1/licences/register",
            json={"email": "dev-trial-user@example.com", "plan": "trial", "name": "Dev Trial User"},
        )
        assert registration.status_code == 201
        verification_code = registration.json()["verification_code"]

        response = await client.post(
            "/v1/licences/verify-email",
            json={"email": "dev-trial-user@example.com", "code": verification_code},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["plan"] == "trial"
    assert data["expires_at"] is None


@pytest.mark.asyncio
async def test_development_trial_can_be_reissued_for_same_email(client):
    development_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="",
        environment="development",
    )

    with patch("app.routers.licences.get_settings", return_value=development_settings):
        first_registration = await client.post(
            "/v1/licences/register",
            json={"email": "dev-reissue-trial@example.com", "plan": "trial"},
        )
        assert first_registration.status_code == 201
        first_verify = await client.post(
            "/v1/licences/verify-email",
            json={
                "email": "dev-reissue-trial@example.com",
                "code": first_registration.json()["verification_code"],
            },
        )
        assert first_verify.status_code == 201

        second_registration = await client.post(
            "/v1/licences/register",
            json={"email": "dev-reissue-trial@example.com", "plan": "trial"},
        )
        assert second_registration.status_code == 201
        second_verify = await client.post(
            "/v1/licences/verify-email",
            json={
                "email": "dev-reissue-trial@example.com",
                "code": second_registration.json()["verification_code"],
            },
        )

    assert second_verify.status_code == 201
    data = second_verify.json()
    assert data["licence_key"].startswith("owlvex_lic_")
    assert data["plan"] == "trial"
    assert data["expires_at"] is None


@pytest.mark.asyncio
async def test_verify_email_registration_emails_licence_when_resend_is_configured(client):
    configured_settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        admin_key="test-admin-key",
        resend_api_key="re_test",
        from_email="verified-sender@example.com",
        environment="production",
    )

    registration = await client.post(
        "/v1/licences/register",
        json={"email": "verify-mail@example.com", "plan": "free", "name": "Verify Mail"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]

    with patch("app.routers.licences.get_settings", return_value=configured_settings), \
         patch("app.routers.licences.send_licence_issued_email") as mock_send_licence_issued_email:
        verify_response = await client.post(
            "/v1/licences/verify-email",
            json={"email": "verify-mail@example.com", "code": verification_code},
        )

    assert verify_response.status_code == 201
    mock_send_licence_issued_email.assert_called_once()


@pytest.mark.asyncio
async def test_verify_email_registration_rejects_invalid_code(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "wrong-code@example.com", "plan": "free"},
    )
    assert registration.status_code == 201

    response = await client.post(
        "/v1/licences/verify-email",
        json={"email": "wrong-code@example.com", "code": "000000"},
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_trial_cannot_be_activated_twice_for_same_email(client):
    first_registration = await client.post(
        "/v1/licences/register",
        json={"email": "one-trial@example.com", "plan": "trial"},
    )
    assert first_registration.status_code == 201
    first_code = first_registration.json()["verification_code"]

    first_verify = await client.post(
        "/v1/licences/verify-email",
        json={"email": "one-trial@example.com", "code": first_code},
    )
    assert first_verify.status_code == 201

    second_registration = await client.post(
        "/v1/licences/register",
        json={"email": "one-trial@example.com", "plan": "trial"},
    )

    assert second_registration.status_code == 403
    assert "already been activated" in second_registration.json()["detail"]


@pytest.mark.asyncio
async def test_trial_cannot_be_reissued_after_customer_delete(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "deleted-trial@example.com", "plan": "trial"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]

    verified = await client.post(
        "/v1/licences/verify-email",
        json={"email": "deleted-trial@example.com", "code": verification_code},
    )
    assert verified.status_code == 201

    deleted = await client.post(
        "/v1/admin/customer/delete",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"email": "deleted-trial@example.com"},
    )
    assert deleted.status_code == 200

    second_registration = await client.post(
        "/v1/licences/register",
        json={"email": "deleted-trial@example.com", "plan": "trial"},
    )

    assert second_registration.status_code == 403
    assert "already been activated" in second_registration.json()["detail"]


@pytest.mark.asyncio
async def test_paid_licence_can_disable_telemetry(client):
    generate_response = await client.post(
        "/v1/licences/generate",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"team_name": "Telemetry Paid", "email": "telemetry-paid@example.com", "plan": "developer", "seats": 1},
    )
    assert generate_response.status_code == 201
    licence_key = generate_response.json()["licence_key"]

    response = await client.post(
        "/v1/licences/telemetry",
        headers={"X-Licence-Key": licence_key},
        json={"enabled": False},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["plan"] == "developer"
    assert data["telemetry_enabled"] is False
    assert data["telemetry_required"] is False


@pytest.mark.asyncio
async def test_free_or_trial_cannot_disable_telemetry(client):
    registration = await client.post(
        "/v1/licences/register",
        json={"email": "telemetry-free@example.com", "plan": "free"},
    )
    assert registration.status_code == 201
    verification_code = registration.json()["verification_code"]
    verify_response = await client.post(
        "/v1/licences/verify-email",
        json={"email": "telemetry-free@example.com", "code": verification_code},
    )
    assert verify_response.status_code == 201
    licence_key = verify_response.json()["licence_key"]

    response = await client.post(
        "/v1/licences/telemetry",
        headers={"X-Licence-Key": licence_key},
        json={"enabled": False},
    )

    assert response.status_code == 400
    assert "require telemetry" in response.json()["detail"]


# ---------------------------------------------------------------------------
# /v1/usage/events
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_usage_event_records_valid_event(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "developer",
        "seats": 1,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": None, "telemetry_enabled": True},
        "expires_at": None,
    }
    with patch("app.routers.usage.validate_licence", return_value=mock_result):
        response = await client.post(
            "/v1/usage/events",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"event_name": "scan_run", "metadata": {"scope": "file", "finding_count": 2, "provider": "anthropic", "model": "claude-sonnet-4", "project_id": "proj_1234", "project_mode": "configured", "project_configured": True}},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["ok"] is True
    assert data["event_name"] == "scan_run"
    assert data["licence_id"] == mock_result["licence_id"]


@pytest.mark.asyncio
async def test_usage_event_rejects_unexpected_fields(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "developer",
        "seats": 1,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": None, "telemetry_enabled": True},
        "expires_at": None,
    }
    with patch("app.routers.usage.validate_licence", return_value=mock_result):
        response = await client.post(
            "/v1/usage/events",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"event_name": "scan_run", "metadata": {}, "source_code": "should not be accepted"},
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_usage_event_rejects_unknown_event_name(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "developer",
        "seats": 1,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": None, "telemetry_enabled": True},
        "expires_at": None,
    }
    with patch("app.routers.usage.validate_licence", return_value=mock_result):
        response = await client.post(
            "/v1/usage/events",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"event_name": "unknown_event", "metadata": {}},
        )

    assert response.status_code == 422
    assert "Unsupported usage event" in response.json()["detail"]


@pytest.mark.asyncio
async def test_usage_event_rejects_unknown_metadata_fields(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "developer",
        "seats": 1,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": None, "telemetry_enabled": True},
        "expires_at": None,
    }
    with patch("app.routers.usage.validate_licence", return_value=mock_result):
        response = await client.post(
            "/v1/usage/events",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"event_name": "scan_run", "metadata": {"scope": "file", "raw_path": "d:\\repo\\secret.ts"}},
        )

    assert response.status_code == 422
    assert "Unsupported metadata fields" in response.json()["detail"]


@pytest.mark.asyncio
async def test_usage_event_returns_success_without_recording_when_telemetry_disabled(client):
    mock_result = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "team_name": "Test Corp",
        "plan": "developer",
        "seats": 1,
        "seats_used": 1,
        "features": {"frameworks": ["OWASP"], "scans_per_day": None, "telemetry_enabled": False, "telemetry_required": False},
        "expires_at": None,
    }
    with patch("app.routers.usage.validate_licence", return_value=mock_result), \
         patch("app.routers.usage.record_usage_event") as mock_record_usage_event:
        response = await client.post(
            "/v1/usage/events",
            headers={"X-Licence-Key": "owlvex_lic_validkey"},
            json={"event_name": "scan_run", "metadata": {"scope": "file"}},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["ok"] is True
    assert data["event_id"] is None
    assert data["telemetry_disabled"] is True
    mock_record_usage_event.assert_not_called()


# ---------------------------------------------------------------------------
# /v1/prompts/build
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_build_prompt_requires_licence(client):
    response = await client.post(
        "/v1/prompts/build",
        json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
    )
    assert response.status_code == 422  # Missing X-Licence-Key header


@pytest.mark.asyncio
async def test_build_prompt_invalid_licence(client):
    with patch("app.routers.prompts.validate_licence", return_value={"valid": False, "reason": "not found"}):
        response = await client.post(
            "/v1/prompts/build",
            headers={"X-Licence-Key": "owlvex_lic_bad"},
            json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_build_prompt_returns_system_prompt(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "CWE"]},
    }
    mock_prompt = {
        "system_prompt": "You are a security engineer. Analyse python code for OWASP.",
        "template_id": str(uuid.uuid4()),
        "template_name": "Default OWASP",
        "rules_loaded": 10,
        "source": "template",
    }
    with patch("app.routers.prompts.validate_licence", return_value=mock_licence), \
         patch("app.routers.prompts.build_prompt", return_value=mock_prompt):
        response = await client.post(
            "/v1/prompts/build",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
        )
    assert response.status_code == 200
    data = response.json()
    assert "system_prompt" in data
    assert "python" in data["system_prompt"]


@pytest.mark.asyncio
async def test_build_prompt_rejects_unexpected_team_context_field(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "CWE"]},
    }
    with patch("app.routers.prompts.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/prompts/build",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "frameworks": ["OWASP"],
                "language": "python",
                "model": "gpt-4o",
                "team_context": "sensitive local project context",
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_build_prompt_rate_limits_repeated_requests(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "CWE"]},
    }
    mock_prompt = {
        "system_prompt": "Prompt",
        "template_id": str(uuid.uuid4()),
        "template_name": "Default",
        "rules_loaded": 3,
        "source": "template",
    }
    with patch("app.routers.prompts.settings.prompt_build_rate_limit", 2), \
         patch("app.routers.prompts.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.prompts.validate_licence", return_value=mock_licence), \
         patch("app.routers.prompts.build_prompt", return_value=mock_prompt):
        for _ in range(2):
            response = await client.post(
                "/v1/prompts/build",
                headers={"X-Licence-Key": "owlvex_lic_valid"},
                json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
            )
            assert response.status_code == 200

        response = await client.post(
            "/v1/prompts/build",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
        )

    assert response.status_code == 429


@pytest.mark.asyncio
async def test_build_prompt_does_not_trust_spoofed_forwarded_for_by_default(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP", "CWE"]},
    }
    mock_prompt = {
        "system_prompt": "Prompt",
        "template_id": str(uuid.uuid4()),
        "template_name": "Default",
        "rules_loaded": 3,
        "source": "template",
    }
    with patch("app.routers.prompts.settings.prompt_build_rate_limit", 2), \
         patch("app.routers.prompts.settings.rate_limit_window_seconds", 60), \
         patch("app.routers.prompts.settings.trust_forwarded_for", False), \
         patch("app.routers.prompts.validate_licence", return_value=mock_licence), \
         patch("app.routers.prompts.build_prompt", return_value=mock_prompt):
        for forwarded_for in ("1.1.1.1", "2.2.2.2"):
            response = await client.post(
                "/v1/prompts/build",
                headers={"X-Licence-Key": "owlvex_lic_valid", "X-Forwarded-For": forwarded_for},
                json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
            )
            assert response.status_code == 200

        response = await client.post(
            "/v1/prompts/build",
            headers={"X-Licence-Key": "owlvex_lic_valid", "X-Forwarded-For": "3.3.3.3"},
            json={"frameworks": ["OWASP"], "language": "python", "model": "gpt-4o"},
        )

    assert response.status_code == 429


# ---------------------------------------------------------------------------
# /v1/scans/record
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_record_scan_requires_licence(client):
    response = await client.post(
        "/v1/scans/record",
        json={"file_name": "app.py", "file_hash": "abc123", "language": "python",
              "model": "gpt-4o", "provider": "openai", "frameworks": ["OWASP"],
              "score": 7.5, "findings_summary": {}, "finding_count": 0},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_record_scan_valid(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"scans_per_day": None, "frameworks": ["OWASP"]},
    }
    mock_scan = MagicMock()
    mock_scan.id = str(uuid.uuid4())
    with patch("app.routers.scans.validate_licence", return_value=mock_licence), \
         patch("app.routers.scans.record_scan", return_value=mock_scan) as mock_record_scan:
        response = await client.post(
            "/v1/scans/record",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "file_name": "app.py",
                "file_hash": "deadbeef" * 8,
                "language": "python",
                "model": "gpt-4o",
                "provider": "openai",
                "frameworks": ["OWASP"],
                "score": 7.5,
                "findings_summary": {"critical": 0, "high": 1, "medium": 2, "low": 0},
                "finding_count": 3,
            },
        )
    assert response.status_code == 200
    assert "scan_id" in response.json()
    assert mock_record_scan.call_args.kwargs["findings_summary"] == {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 0,
    }


@pytest.mark.asyncio
async def test_record_scan_rejects_prompt_snapshot_field(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"scans_per_day": None, "frameworks": ["OWASP"]},
    }
    with patch("app.routers.scans.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/scans/record",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "file_name": "app.py",
                "file_hash": "deadbeef" * 8,
                "language": "python",
                "model": "gpt-4o",
                "provider": "openai",
                "frameworks": ["OWASP"],
                "score": 7.5,
                "findings_summary": {"critical": 0, "high": 1, "medium": 2, "low": 0},
                "finding_count": 3,
                "prompt_snapshot": "full assembled system prompt",
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_record_scan_rejects_unexpected_findings_summary_fields(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"scans_per_day": None, "frameworks": ["OWASP"]},
    }
    with patch("app.routers.scans.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/scans/record",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "file_name": "app.py",
                "file_hash": "deadbeef" * 8,
                "language": "python",
                "model": "gpt-4o",
                "provider": "openai",
                "frameworks": ["OWASP"],
                "score": 7.5,
                "findings_summary": {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 0,
                    "info": 99,
                },
                "finding_count": 3,
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_compare_scan_returns_extension_compatible_shape(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"comparison": True, "frameworks": ["OWASP"]},
    }
    comparison_payload = {
        "comparison_id": str(uuid.uuid4()),
        "score_a": 6.0,
        "score_b": 8.0,
        "score_change": 2.0,
        "new_findings": 1,
        "resolved_findings": 2,
        "agreed_findings": 3,
        "new_finding_details": [
            {
                "issue_id": "owlvex.issue.command_injection.001",
                "line": 10,
                "framework": "OWASP",
                "rule_code": "GR-001",
                "severity": "HIGH",
                "title": "Command Injection",
            }
        ],
        "resolved_finding_details": [
            {
                "issue_id": "owlvex.issue.sql_injection.001",
                "line": 5,
                "framework": "OWASP",
                "rule_code": "SQ-001",
                "severity": "HIGH",
                "title": "SQL Injection",
            }
        ],
        "canonical_changes": [],
        "summary": {"verdict": "improved"},
    }

    with patch("app.routers.scans.validate_licence", return_value=mock_licence), \
         patch("app.routers.scans.record_comparison", return_value=comparison_payload):
        response = await client.post(
            "/v1/scans/compare",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "scan_a_id": str(uuid.uuid4()),
                "scan_b_id": str(uuid.uuid4()),
                "findings_a": [],
                "findings_b": [],
                "score_a": 6.0,
                "score_b": 8.0,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["new_findings"] == 1
    assert data["resolved_findings"] == 2
    assert isinstance(data["new_finding_details"], list)
    assert isinstance(data["resolved_finding_details"], list)


@pytest.mark.asyncio
async def test_compare_scan_rejects_unexpected_extra_fields(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"comparison": True, "frameworks": ["OWASP"]},
    }
    with patch("app.routers.scans.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/scans/compare",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "scan_a_id": str(uuid.uuid4()),
                "scan_b_id": str(uuid.uuid4()),
                "findings_a": [],
                "findings_b": [],
                "score_a": 6.0,
                "score_b": 8.0,
                "source_code": "should never be accepted here",
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_compare_scan_rejects_nested_source_bearing_fields(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"comparison": True, "frameworks": ["OWASP"]},
    }
    with patch("app.routers.scans.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/scans/compare",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "scan_a_id": str(uuid.uuid4()),
                "scan_b_id": str(uuid.uuid4()),
                "findings_a": [
                    {
                        "issue_id": "owlvex.issue.nosql_injection.001",
                        "title": "NoSQL Injection",
                        "line": 12,
                        "source_code": "db.users.find(req.body.filter)",
                    }
                ],
                "findings_b": [],
                "score_a": 6.0,
                "score_b": 8.0,
            },
        )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# /v1/policies/evaluate
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_policy_evaluation_requires_licence(client):
    response = await client.post(
        "/v1/policies/evaluate",
        json={"findings": [], "policy": {"policy": "block", "conditions": {}}},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_policy_evaluation_returns_decision(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP"]},
    }
    with patch("app.routers.policies.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/policies/evaluate",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "findings": [
                    {
                        "issue_id": "owlvex.issue.sql_injection.001",
                        "severity": "HIGH",
                        "title": "SQL Injection",
                        "line": 5,
                    }
                ],
                "policy": {
                    "policy": "block",
                    "conditions": {
                        "issue_ids": ["owlvex.issue.sql_injection.001"],
                        "severity": ["HIGH", "CRITICAL"],
                    },
                },
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert data["matched_count"] == 1


@pytest.mark.asyncio
async def test_policy_evaluation_rejects_nested_unexpected_fields(client):
    mock_licence = {
        "valid": True,
        "licence_id": str(uuid.uuid4()),
        "plan": "developer",
        "team_name": "Test",
        "features": {"frameworks": ["OWASP"]},
    }
    with patch("app.routers.policies.validate_licence", return_value=mock_licence):
        response = await client.post(
            "/v1/policies/evaluate",
            headers={"X-Licence-Key": "owlvex_lic_valid"},
            json={
                "findings": [
                    {
                        "issue_id": "owlvex.issue.sql_injection.001",
                        "severity": "HIGH",
                        "title": "SQL Injection",
                        "line": 5,
                        "source_code": "select * from users",
                    }
                ],
                "policy": {
                    "policy": "block",
                    "conditions": {
                        "issue_ids": ["owlvex.issue.sql_injection.001"],
                        "severity": ["HIGH", "CRITICAL"],
                    },
                },
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_billing_webhook_is_disabled_by_default(client):
    response = await client.post(
        "/v1/billing/webhook/stripe",
        headers={"Stripe-Signature": "test-signature"},
        content=b"{}",
    )

    assert response.status_code == 503
