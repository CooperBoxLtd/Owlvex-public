import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.scan_recorder import _resolve_prompt_id, record_comparison


@pytest.mark.asyncio
async def test_resolve_prompt_id_returns_none_when_missing():
    db = AsyncMock()

    resolved = await _resolve_prompt_id(db, str(uuid.uuid4()), None)

    assert resolved is None
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_prompt_id_keeps_team_prompt_ids():
    db = AsyncMock()
    expected_id = str(uuid.uuid4())
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = expected_id
    db.execute.return_value = execute_result

    resolved = await _resolve_prompt_id(db, str(uuid.uuid4()), expected_id)

    assert resolved == expected_id
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_resolve_prompt_id_drops_unknown_prompt_ids():
    db = AsyncMock()
    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    db.execute.return_value = execute_result

    resolved = await _resolve_prompt_id(db, str(uuid.uuid4()), str(uuid.uuid4()))

    assert resolved is None


@pytest.mark.asyncio
async def test_resolve_prompt_id_degrades_gracefully_on_db_errors():
    db = AsyncMock()
    db.execute.side_effect = RuntimeError("db unavailable")

    resolved = await _resolve_prompt_id(db, str(uuid.uuid4()), str(uuid.uuid4()))

    assert resolved is None


@pytest.mark.asyncio
async def test_record_comparison_includes_canonical_issue_changes():
    db = AsyncMock()
    db.commit.return_value = None
    db.refresh.return_value = None

    comparison = await record_comparison(
        db=db,
        licence_id=str(uuid.uuid4()),
        scan_a_id=str(uuid.uuid4()),
        scan_b_id=str(uuid.uuid4()),
        findings_a=[
            {
                "issue_id": "owlvex.issue.sql_injection.001",
                "canonical_title": "Unsanitized SQL query construction",
                "line": 10,
                "framework": "OWASP",
                "rule_code": "OWASP-A03",
                "severity": "HIGH",
                "title": "SQL Injection",
            },
            {
                "issue_id": "owlvex.issue.sql_injection.001",
                "canonical_title": "Unsanitized SQL query construction",
                "line": 20,
                "framework": "OWASP",
                "rule_code": "OWASP-A03",
                "severity": "HIGH",
                "title": "SQL Injection",
            },
        ],
        findings_b=[
            {
                "issue_id": "owlvex.issue.sql_injection.001",
                "canonical_title": "Unsanitized SQL query construction",
                "line": 10,
                "framework": "OWASP",
                "rule_code": "OWASP-A03",
                "severity": "HIGH",
                "title": "SQL Injection",
            },
        ],
        score_a=4.0,
        score_b=7.0,
    )

    assert comparison["summary"]["verdict"] == "improved"
    assert comparison["canonical_changes"][0]["issue_id"] == "owlvex.issue.sql_injection.001"
    assert comparison["canonical_changes"][0]["count_a"] == 2
    assert comparison["canonical_changes"][0]["count_b"] == 1
    assert comparison["canonical_changes"][0]["delta"] == -1
