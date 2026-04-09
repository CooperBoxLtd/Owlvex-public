"""
Unit tests for prompt_builder — variable substitution, fallback, rule formatting.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.prompt_builder import (
    build_prompt,
    _substitute_variables,
    _format_rules,
    _hardcoded_fallback,
    _canonical_resolution_guidance,
)


# ---------------------------------------------------------------------------
# _substitute_variables
# ---------------------------------------------------------------------------
class TestSubstituteVariables:
    def test_replaces_language(self):
        result = _substitute_variables("Analyse {language} code.", "python", ["OWASP"], "MEDIUM", "")
        assert "python" in result
        assert "{language}" not in result

    def test_replaces_frameworks(self):
        result = _substitute_variables("Use {frameworks}.", "go", ["OWASP", "CWE"], "HIGH", "")
        assert "OWASP, CWE" in result

    def test_replaces_severity_threshold(self):
        result = _substitute_variables("Threshold: {severity_threshold}", "python", [], "HIGH", "")
        assert "HIGH" in result

    def test_team_context_empty_string(self):
        result = _substitute_variables("{team_context}", "python", [], "LOW", "")
        assert result == ""

    def test_team_context_injected(self):
        result = _substitute_variables("{team_context}", "python", [], "LOW", "PCI environment")
        assert "PCI environment" in result


# ---------------------------------------------------------------------------
# _format_rules
# ---------------------------------------------------------------------------
class TestFormatRules:
    def _make_rule(self, code, title, severity, prompt_hints=None):
        r = MagicMock()
        r.code = code
        r.title = title
        r.severity = severity
        r.prompt_hints = prompt_hints
        return r

    def test_empty_rules_returns_empty_string(self):
        assert _format_rules([]) == ""

    def test_single_rule_format(self):
        rule = self._make_rule("OWASP-A03", "Injection", "CRITICAL")
        result = _format_rules([rule])
        assert "OWASP-A03" in result
        assert "Injection" in result
        assert "CRITICAL" in result

    def test_prompt_hints_appended(self):
        rule = self._make_rule("OWASP-A03", "Injection", "CRITICAL", "Look for parameterised queries")
        result = _format_rules([rule])
        assert "Look for parameterised queries" in result

    def test_multiple_rules_each_on_own_line(self):
        rules = [
            self._make_rule("OWASP-A01", "Access Control", "HIGH"),
            self._make_rule("OWASP-A03", "Injection", "CRITICAL"),
        ]
        result = _format_rules(rules)
        lines = result.strip().split("\n")
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# _hardcoded_fallback
# ---------------------------------------------------------------------------
class TestHardcodedFallback:
    def test_returns_dict_with_required_keys(self):
        result = _hardcoded_fallback(["OWASP"], "python", "MEDIUM", "")
        assert "system_prompt" in result
        assert result["source"] == "fallback"
        assert result["template_id"] is None
        assert result["rules_loaded"] == 0

    def test_prompt_contains_frameworks(self):
        result = _hardcoded_fallback(["STRIDE", "CWE"], "java", "HIGH", "")
        assert "STRIDE" in result["system_prompt"]
        assert "CWE" in result["system_prompt"]

    def test_prompt_contains_language(self):
        result = _hardcoded_fallback(["OWASP"], "rust", "LOW", "")
        assert "rust" in result["system_prompt"]

    def test_team_context_included_when_provided(self):
        result = _hardcoded_fallback(["OWASP"], "python", "MEDIUM", "Healthcare system - HIPAA applies")
        assert "Healthcare" in result["system_prompt"]

    def test_prompt_contains_canonical_guidance(self):
        result = _hardcoded_fallback(["OWASP"], "python", "MEDIUM", "")
        assert "Resolve each finding to the closest Owlvex canonical issue" in result["system_prompt"]
        assert '"issue_id"' in result["system_prompt"]
        assert '"matched_signals"' in result["system_prompt"]


class TestCanonicalResolutionGuidance:
    def test_guidance_mentions_optional_canonical_fields(self):
        guidance = _canonical_resolution_guidance()
        assert "issue_id" in guidance
        assert "stride" in guidance
        assert "matched_signals" in guidance


# ---------------------------------------------------------------------------
# build_prompt integration (with mocked DB)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_build_prompt_uses_custom_prompt_directly():
    db = AsyncMock()
    result = await build_prompt(
        db,
        frameworks=["OWASP"],
        language="python",
        model="gpt-4o",
        custom_prompt="Custom instruction: {language}",
    )
    assert result["source"] == "custom"
    assert "python" in result["system_prompt"]
    assert result["template_id"] is None


@pytest.mark.asyncio
async def test_build_prompt_filters_disallowed_frameworks():
    db = AsyncMock()
    result = await build_prompt(
        db,
        frameworks=["OWASP", "HIPAA"],
        language="python",
        model="gpt-4o",
        allowed_frameworks=["OWASP"],
        custom_prompt="Frameworks: {frameworks}",
    )
    assert "HIPAA" not in result["system_prompt"]
    assert "OWASP" in result["system_prompt"]


@pytest.mark.asyncio
async def test_build_prompt_falls_back_to_owasp_when_all_filtered():
    db = AsyncMock()
    with patch("app.services.prompt_builder._find_template", return_value=None):
        result = await build_prompt(
            db,
            frameworks=["HIPAA"],
            language="python",
            model="gpt-4o",
            allowed_frameworks=["OWASP"],
        )
    # All requested frameworks filtered out -> defaults to OWASP, then hits fallback
    assert result["source"] == "fallback"
    assert "OWASP" in result["system_prompt"]


@pytest.mark.asyncio
async def test_build_prompt_uses_fallback_when_no_template():
    db = AsyncMock()
    with patch("app.services.prompt_builder._find_template", return_value=None):
        result = await build_prompt(
            db,
            frameworks=["OWASP"],
            language="go",
            model="gpt-4o",
        )
    assert result["source"] == "fallback"


@pytest.mark.asyncio
async def test_build_prompt_substitutes_template_variables():
    db = AsyncMock()
    mock_template = MagicMock()
    mock_template.id = "template-uuid"
    mock_template.name = "Test Template"
    mock_template.template = "Analyse {language} using {frameworks} at {severity_threshold}. {team_context}"

    with patch("app.services.prompt_builder._find_template", return_value=mock_template), \
         patch("app.services.prompt_builder._load_rules", return_value=[]):
        result = await build_prompt(
            db,
            frameworks=["OWASP", "CWE"],
            language="typescript",
            model="claude-sonnet-4-6",
            severity_threshold="HIGH",
            team_context="FinTech API",
        )

    assert "typescript" in result["system_prompt"]
    assert "OWASP, CWE" in result["system_prompt"]
    assert "HIGH" in result["system_prompt"]
    assert "FinTech API" in result["system_prompt"]
    assert result["source"] == "template"
    assert result["template_name"] == "Test Template"
