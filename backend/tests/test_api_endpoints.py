"""
Integration tests for the FastAPI endpoints using an in-memory database.
Covers: /health, /v1/licences/validate, /v1/licences/generate, /v1/prompts/build.
"""
import pytest
import json
import uuid
from unittest.mock import patch, AsyncMock, MagicMock

from unittest.mock import MagicMock
from app.services.licence_service import hash_licence_key, generate_licence_key


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
         patch("app.services.scan_recorder.record_scan", return_value=mock_scan):
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
