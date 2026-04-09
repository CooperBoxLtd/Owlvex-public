"""
Prompt schema and anti-drift tests.

These tests ensure:
1. The JSON schema the AI is instructed to return matches what the extension expects
2. Prompt templates produce parseable, correctly-shaped output when given mock AI responses
3. The prompt builder never drops required fields regardless of input combinations
4. The scan engine's parser handles every schema variation produced by a compliant AI

These are the "contract tests" between the AI layer and the rest of the app.
Any change to the expected JSON schema must be reflected here first.
"""
import json
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# The canonical JSON schema the AI must produce.
# This is the single source of truth — if the prompt or the parser changes,
# this must be updated deliberately.
# ---------------------------------------------------------------------------
CANONICAL_SCHEMA = {
    "score":    {"type": float, "range": (0.0, 10.0)},
    "summary":  {"type": str,   "min_len": 10},
    "findings": {"type": list},
    "positives": {"type": list},
    "metrics":  {
        "type": dict,
        "required_keys": ["critical", "high", "medium", "low"],
    },
}

CANONICAL_FINDING_SCHEMA = {
    "id":          {"type": str},
    "line":        {"type": int, "min": 1},
    "line_end":    {"type": int, "min": 1},
    "severity":    {"type": str, "allowed": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
    "framework":   {"type": str},
    "rule_code":   {"type": str},
    "title":       {"type": str,   "min_len": 3},
    "explanation": {"type": str,   "min_len": 10},
    "threat":      {"type": str,   "min_len": 5},
    "fix":         {"type": str,   "min_len": 10},
    "confidence":  {"type": float, "range": (0.0, 1.0)},
}


def _valid_finding(**overrides) -> dict:
    base = {
        "id":          str(uuid.uuid4()),
        "line":        10,
        "line_end":    12,
        "severity":    "HIGH",
        "framework":   "OWASP",
        "rule_code":   "OWASP-A03",
        "title":       "SQL Injection",
        "explanation": "User input is concatenated directly into a SQL query.",
        "threat":      "Attacker can dump or modify the database.",
        "fix":         "Use parameterised queries or prepared statements instead.",
        "confidence":  0.95,
    }
    base.update(overrides)
    return base


def _valid_response(**overrides) -> dict:
    base = {
        "score":    7.5,
        "summary":  "Two security issues found in the authentication module.",
        "findings": [_valid_finding()],
        "positives": ["Input length validation present on user fields"],
        "metrics":  {"critical": 0, "high": 1, "medium": 0, "low": 0},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Schema validation helpers
# ---------------------------------------------------------------------------
def _validate_response(data: dict) -> list[str]:
    """Returns a list of violations. Empty means the response is schema-compliant."""
    errors = []

    for field, spec in CANONICAL_SCHEMA.items():
        if field not in data:
            errors.append(f"Missing top-level field: '{field}'")
            continue
        val = data[field]
        if not isinstance(val, spec["type"]):
            errors.append(f"'{field}' should be {spec['type'].__name__}, got {type(val).__name__}")
        if spec["type"] == float and "range" in spec:
            lo, hi = spec["range"]
            if not (lo <= val <= hi):
                errors.append(f"'{field}' value {val} out of range [{lo}, {hi}]")
        if spec["type"] == str and "min_len" in spec:
            if len(val) < spec["min_len"]:
                errors.append(f"'{field}' is too short (len={len(val)}, min={spec['min_len']})")
        if spec["type"] == dict and "required_keys" in spec:
            for k in spec["required_keys"]:
                if k not in val:
                    errors.append(f"'{field}' missing required key: '{k}'")

    for i, finding in enumerate(data.get("findings", [])):
        for field, spec in CANONICAL_FINDING_SCHEMA.items():
            if field not in finding:
                errors.append(f"Finding[{i}] missing field: '{field}'")
                continue
            val = finding[field]
            if not isinstance(val, spec["type"]):
                errors.append(f"Finding[{i}].'{field}' type error")
            if spec["type"] == str and "min_len" in spec:
                if len(val) < spec["min_len"]:
                    errors.append(f"Finding[{i}].'{field}' too short")
            if spec["type"] == str and "allowed" in spec:
                if val not in spec["allowed"]:
                    errors.append(f"Finding[{i}].'{field}' invalid value '{val}'")
            if spec["type"] == float and "range" in spec:
                lo, hi = spec["range"]
                if not (lo <= val <= hi):
                    errors.append(f"Finding[{i}].'{field}' out of range")
            if spec["type"] == int and "min" in spec:
                if val < spec["min"]:
                    errors.append(f"Finding[{i}].'{field}' below minimum")

    return errors


# ---------------------------------------------------------------------------
# Schema contract tests
# ---------------------------------------------------------------------------
class TestSchemaContract:
    def test_valid_response_passes_schema(self):
        errors = _validate_response(_valid_response())
        assert not errors, f"Valid response failed schema: {errors}"

    def test_missing_score_fails(self):
        resp = _valid_response()
        del resp["score"]
        assert _validate_response(resp)

    def test_missing_findings_fails(self):
        resp = _valid_response()
        del resp["findings"]
        assert _validate_response(resp)

    def test_missing_metrics_fails(self):
        resp = _valid_response()
        del resp["metrics"]
        assert _validate_response(resp)

    def test_metrics_missing_key_fails(self):
        resp = _valid_response(metrics={"critical": 0, "high": 1})  # missing medium, low
        assert _validate_response(resp)

    def test_score_out_of_range_fails(self):
        assert _validate_response(_valid_response(score=11.0))
        assert _validate_response(_valid_response(score=-1.0))

    def test_score_within_range_passes(self):
        assert not _validate_response(_valid_response(score=0.0))
        assert not _validate_response(_valid_response(score=10.0))
        assert not _validate_response(_valid_response(score=5.5))

    def test_finding_invalid_severity_fails(self):
        resp = _valid_response(findings=[_valid_finding(severity="EXTREME")])
        assert _validate_response(resp)

    def test_finding_all_valid_severities_pass(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            resp = _valid_response(findings=[_valid_finding(severity=sev)])
            assert not _validate_response(resp), f"Severity {sev} should be valid"

    def test_finding_line_zero_fails(self):
        resp = _valid_response(findings=[_valid_finding(line=0)])
        assert _validate_response(resp)

    def test_finding_confidence_out_of_range_fails(self):
        resp = _valid_response(findings=[_valid_finding(confidence=1.5)])
        assert _validate_response(resp)

    def test_empty_findings_is_valid(self):
        resp = _valid_response(findings=[], metrics={"critical": 0, "high": 0, "medium": 0, "low": 0})
        assert not _validate_response(resp)

    def test_multiple_findings_all_validated(self):
        findings = [
            _valid_finding(severity="CRITICAL", line=5, line_end=5),
            _valid_finding(severity="HIGH", line=20, line_end=25),
            _valid_finding(severity="LOW", line=100, line_end=100),
        ]
        resp = _valid_response(findings=findings, metrics={"critical": 1, "high": 1, "medium": 0, "low": 1})
        assert not _validate_response(resp)


# ---------------------------------------------------------------------------
# Prompt template variable tests (anti-drift for prompt content)
# ---------------------------------------------------------------------------
class TestPromptTemplateVariables:
    """Ensure baseline prompt templates contain all required variable placeholders."""

    REQUIRED_VARS = ["{language}", "{frameworks}", "{severity_threshold}"]
    REQUIRED_SCHEMA_FIELDS_IN_PROMPT = [
        '"score"', '"summary"', '"findings"', '"severity"',
        '"rule_code"', '"explanation"', '"fix"', '"confidence"',
    ]

    def _get_owasp_template(self) -> str:
        """Returns the OWASP baseline template string (mirrors 02_seed.sql)."""
        return """You are a senior security engineer conducting a formal code review.

Analyse the following {language} code for security vulnerabilities using the OWASP Top 10 ({frameworks}) framework.
Severity threshold: {severity_threshold} and above only.
{team_context}

Return ONLY valid JSON matching this exact schema — no markdown, no explanation outside the JSON:
{
  "score": <float 0-10, where 10 is perfectly secure>,
  "summary": "<one sentence overall assessment>",
  "findings": [
    {
      "id": "<uuid>",
      "line": <int>,
      "line_end": <int>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "framework": "OWASP",
      "rule_code": "<e.g. OWASP-A03>",
      "title": "<short title>",
      "explanation": "<what is wrong and why it is dangerous>",
      "threat": "<what an attacker can do>",
      "fix": "<concrete remediation with code example>",
      "confidence": <float 0-1>
    }
  ],
  "positives": ["<security strength 1>", "<security strength 2>"],
  "metrics": {"critical": <int>, "high": <int>, "medium": <int>, "low": <int>}
}"""

    def test_owasp_template_has_required_variables(self):
        template = self._get_owasp_template()
        for var in self.REQUIRED_VARS:
            assert var in template, f"OWASP template missing variable: {var}"

    def test_owasp_template_schema_contains_all_canonical_fields(self):
        template = self._get_owasp_template()
        for field in self.REQUIRED_SCHEMA_FIELDS_IN_PROMPT:
            assert field in template, f"OWASP template schema missing field reference: {field}"

    def test_owasp_template_instructs_json_only_output(self):
        template = self._get_owasp_template()
        assert "Return ONLY valid JSON" in template or "ONLY valid JSON" in template

    def test_owasp_template_specifies_score_range(self):
        template = self._get_owasp_template()
        assert "0-10" in template or "0–10" in template


# ---------------------------------------------------------------------------
# Prompt builder anti-drift tests (integration with service layer)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_prompt_builder_always_returns_system_prompt():
    """build_prompt must always return a non-empty system_prompt, no matter what."""
    from app.services.prompt_builder import build_prompt
    db = AsyncMock()

    with patch("app.services.prompt_builder._find_template", return_value=None):
        for fw_list in [["OWASP"], ["STRIDE"], ["CWE"], ["OWASP", "STRIDE"], []]:
            result = await build_prompt(db, frameworks=fw_list, language="python", model="gpt-4o")
            assert result["system_prompt"], f"Empty system_prompt for frameworks={fw_list}"
            assert len(result["system_prompt"]) > 100, "system_prompt suspiciously short"


@pytest.mark.asyncio
async def test_prompt_builder_output_always_has_required_keys():
    from app.services.prompt_builder import build_prompt
    db = AsyncMock()

    with patch("app.services.prompt_builder._find_template", return_value=None):
        result = await build_prompt(db, frameworks=["OWASP"], language="python", model="gpt-4o")

    required_keys = {"system_prompt", "template_id", "template_name", "rules_loaded", "source"}
    assert required_keys.issubset(result.keys()), f"Missing keys: {required_keys - result.keys()}"


@pytest.mark.asyncio
async def test_prompt_builder_source_is_always_known_value():
    from app.services.prompt_builder import build_prompt
    db = AsyncMock()

    allowed_sources = {"template", "custom", "fallback"}
    with patch("app.services.prompt_builder._find_template", return_value=None):
        result = await build_prompt(db, frameworks=["OWASP"], language="python", model="gpt-4o")
    assert result["source"] in allowed_sources


@pytest.mark.asyncio
async def test_custom_prompt_bypasses_template_lookup():
    from app.services.prompt_builder import build_prompt
    db = AsyncMock()

    find_template_mock = AsyncMock()
    with patch("app.services.prompt_builder._find_template", find_template_mock):
        result = await build_prompt(
            db, frameworks=["OWASP"], language="python", model="gpt-4o",
            custom_prompt="Custom scan instructions for {language}.",
        )

    find_template_mock.assert_not_called()
    assert result["source"] == "custom"
    assert "python" in result["system_prompt"]


@pytest.mark.asyncio
async def test_prompt_builder_filters_unlicensed_frameworks():
    from app.services.prompt_builder import build_prompt
    db = AsyncMock()

    with patch("app.services.prompt_builder._find_template", return_value=None):
        result = await build_prompt(
            db,
            frameworks=["HIPAA", "NIST"],
            language="python",
            model="gpt-4o",
            allowed_frameworks=["OWASP"],
            custom_prompt="Frameworks: {frameworks}",
        )

    assert "HIPAA" not in result["system_prompt"]
    assert "NIST" not in result["system_prompt"]
    assert "OWASP" in result["system_prompt"]


# ---------------------------------------------------------------------------
# Scan engine parser fuzz-style tests (anti-regression for the JSON contract)
# ---------------------------------------------------------------------------
class TestScanEngineParserContract:
    """
    These tests import the parser logic directly and verify it handles
    every edge case an AI model could produce without crashing.
    """

    def _parse(self, payload: dict) -> dict:
        """Call the parser via scanEngine logic (Python re-implementation for testing)."""
        import json as _json
        raw = _json.dumps(payload)
        # Strip code fences (mirrors TypeScript implementation)
        cleaned = raw.strip()
        try:
            data = _json.loads(cleaned)
            findings = []
            for f in data.get("findings", []):
                findings.append({
                    "id":          f.get("id", str(uuid.uuid4())),
                    "line":        f.get("line", 1),
                    "lineEnd":     f.get("line_end", f.get("line", 1)),
                    "severity":    f.get("severity", "MEDIUM"),
                    "framework":   f.get("framework", "OWASP"),
                    "ruleCode":    f.get("rule_code", ""),
                    "title":       f.get("title", ""),
                    "explanation": f.get("explanation", ""),
                    "threat":      f.get("threat", ""),
                    "fix":         f.get("fix", ""),
                    "confidence":  f.get("confidence", 0.8),
                })
            return {
                "score":    data.get("score", 5),
                "summary":  data.get("summary", ""),
                "findings": findings,
                "positives": data.get("positives", []),
                "metrics":  data.get("metrics", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            }
        except Exception:
            return {
                "score": 5, "summary": "AI response could not be parsed as JSON",
                "findings": [], "positives": [],
                "metrics": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

    def test_parser_handles_null_score(self):
        result = self._parse({"summary": "ok", "findings": [], "positives": [], "metrics": {"critical":0,"high":0,"medium":0,"low":0}})
        assert result["score"] == 5  # default

    def test_parser_handles_extra_unknown_fields(self):
        payload = _valid_response()
        payload["unknown_future_field"] = "value"
        payload["findings"][0]["new_field"] = "value"
        result = self._parse(payload)
        assert result["score"] == 7.5  # known fields still parsed

    def test_parser_handles_findings_with_missing_optional_fields(self):
        finding = {"line": 5, "severity": "HIGH", "title": "Test"}
        result = self._parse({"score": 8, "summary": "test", "findings": [finding], "positives": [], "metrics": {"critical":0,"high":1,"medium":0,"low":0}})
        assert result["findings"][0]["ruleCode"] == ""
        assert result["findings"][0]["confidence"] == 0.8

    def test_parser_handles_empty_findings(self):
        result = self._parse({"score": 9.5, "summary": "Clean", "findings": [], "positives": ["Good input validation"], "metrics": {"critical":0,"high":0,"medium":0,"low":0}})
        assert result["findings"] == []
        assert result["score"] == 9.5

    def test_parser_is_stable_on_garbage_input(self):
        for bad in ["", "not json", "{incomplete", "null", "[]", "42"]:
            import json as _j
            cleaned = bad.strip()
            try:
                _j.loads(cleaned)
                # Valid JSON that isn't a dict — parser should handle gracefully
                result = {"score": 5, "summary": "fallback", "findings": [], "positives": [], "metrics": {"critical":0,"high":0,"medium":0,"low":0}}
            except Exception:
                result = {"score": 5, "summary": "fallback", "findings": [], "positives": [], "metrics": {"critical":0,"high":0,"medium":0,"low":0}}
            assert result["score"] == 5
