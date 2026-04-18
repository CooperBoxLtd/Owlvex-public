"""
Integration tests for the FastAPI endpoints using an in-memory database.
Covers the production extension/backend contract surfaces.
"""
import pytest
import uuid
from unittest.mock import patch, MagicMock


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
         patch("app.routers.scans.record_scan", return_value=mock_scan):
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
