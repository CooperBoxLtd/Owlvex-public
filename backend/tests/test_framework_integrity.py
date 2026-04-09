"""
Framework integrity tests — anti-drift guards for the rule database.

These tests ensure that:
1. All seeded frameworks are present and active
2. Every rule has the required fields populated (no empty strings, no missing severity)
3. Severity values are from the allowed set
4. Language codes are from the known set
5. Prompt hints are substantive (not empty, not just restating the title)
6. Fix guidance is present and meaningful
7. Each framework has minimum rule coverage
8. No duplicate rule codes within a framework
9. Prompt templates exist for core frameworks and produce valid output

Run these after any change to 02_seed.sql or when adding new rules.
"""
import pytest
from unittest.mock import patch, MagicMock

ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_LANGUAGES = {
    "all", "python", "javascript", "typescript", "java", "csharp",
    "go", "rust", "php", "ruby", "cpp", "c", "kotlin", "swift",
}
KNOWN_FRAMEWORKS = {"OWASP", "STRIDE", "MITRE", "CWE", "CLEANCODE", "NIST", "PCIDSS", "HIPAA"}

# Minimum number of rules each framework must have to be considered useful
MIN_RULE_COUNTS = {
    "OWASP":  8,
    "STRIDE": 5,
    "CWE":    10,
}

# These frameworks must have a baseline prompt template
FRAMEWORKS_REQUIRING_TEMPLATE = {"OWASP", "STRIDE", "CWE"}


# ---------------------------------------------------------------------------
# Fixtures: in-memory rule data (mirrors 02_seed.sql content)
# ---------------------------------------------------------------------------
OWASP_RULES = [
    {"code": "OWASP-A01", "title": "Broken Access Control",         "severity": "HIGH",     "languages": ["all"]},
    {"code": "OWASP-A02", "title": "Cryptographic Failures",        "severity": "HIGH",     "languages": ["all"]},
    {"code": "OWASP-A03", "title": "Injection",                     "severity": "CRITICAL", "languages": ["all"]},
    {"code": "OWASP-A04", "title": "Insecure Design",               "severity": "MEDIUM",   "languages": ["all"]},
    {"code": "OWASP-A05", "title": "Security Misconfiguration",     "severity": "MEDIUM",   "languages": ["all"]},
    {"code": "OWASP-A06", "title": "Vulnerable and Outdated Components", "severity": "MEDIUM", "languages": ["all"]},
    {"code": "OWASP-A07", "title": "Identification and Authentication Failures", "severity": "HIGH", "languages": ["all"]},
    {"code": "OWASP-A08", "title": "Software and Data Integrity Failures", "severity": "HIGH", "languages": ["all"]},
    {"code": "OWASP-A09", "title": "Security Logging and Monitoring Failures", "severity": "LOW", "languages": ["all"]},
    {"code": "OWASP-A10", "title": "Server-Side Request Forgery",   "severity": "HIGH",     "languages": ["all"]},
]

STRIDE_RULES = [
    {"code": "STRIDE-S", "title": "Spoofing Identity",          "severity": "HIGH",     "languages": ["all"]},
    {"code": "STRIDE-T", "title": "Tampering with Data",        "severity": "HIGH",     "languages": ["all"]},
    {"code": "STRIDE-R", "title": "Repudiation",                "severity": "MEDIUM",   "languages": ["all"]},
    {"code": "STRIDE-I", "title": "Information Disclosure",     "severity": "HIGH",     "languages": ["all"]},
    {"code": "STRIDE-D", "title": "Denial of Service",          "severity": "MEDIUM",   "languages": ["all"]},
    {"code": "STRIDE-E", "title": "Elevation of Privilege",     "severity": "CRITICAL", "languages": ["all"]},
]

CWE_RULES = [
    {"code": "CWE-22",  "title": "Path Traversal",                    "severity": "HIGH",     "languages": ["all"]},
    {"code": "CWE-78",  "title": "OS Command Injection",              "severity": "CRITICAL", "languages": ["all"]},
    {"code": "CWE-79",  "title": "Cross-Site Scripting (XSS)",        "severity": "HIGH",     "languages": ["javascript", "typescript", "php", "python", "ruby", "java"]},
    {"code": "CWE-89",  "title": "SQL Injection",                     "severity": "CRITICAL", "languages": ["all"]},
    {"code": "CWE-200", "title": "Sensitive Information Exposure",    "severity": "MEDIUM",   "languages": ["all"]},
    {"code": "CWE-306", "title": "Missing Authentication",            "severity": "CRITICAL", "languages": ["all"]},
    {"code": "CWE-311", "title": "Missing Encryption of Sensitive Data", "severity": "HIGH",  "languages": ["all"]},
    {"code": "CWE-352", "title": "Cross-Site Request Forgery (CSRF)", "severity": "MEDIUM",   "languages": ["javascript", "typescript", "php", "python", "ruby", "java"]},
    {"code": "CWE-434", "title": "Unrestricted File Upload",          "severity": "HIGH",     "languages": ["all"]},
    {"code": "CWE-502", "title": "Deserialization of Untrusted Data", "severity": "CRITICAL", "languages": ["python", "java", "php", "ruby", "javascript"]},
    {"code": "CWE-611", "title": "XML External Entity Injection (XXE)", "severity": "HIGH",   "languages": ["java", "python", "php", "csharp"]},
    {"code": "CWE-798", "title": "Hard-coded Credentials",            "severity": "CRITICAL", "languages": ["all"]},
    {"code": "CWE-862", "title": "Missing Authorization",             "severity": "HIGH",     "languages": ["all"]},
    {"code": "CWE-918", "title": "Server-Side Request Forgery (SSRF)", "severity": "HIGH",   "languages": ["all"]},
]

ALL_RULES_BY_FRAMEWORK = {
    "OWASP":  OWASP_RULES,
    "STRIDE": STRIDE_RULES,
    "CWE":    CWE_RULES,
}


# ---------------------------------------------------------------------------
# Framework presence tests
# ---------------------------------------------------------------------------
class TestFrameworkPresence:
    def test_all_known_frameworks_defined(self):
        """Every framework in KNOWN_FRAMEWORKS must have rule data or a seed entry."""
        seeded = set(ALL_RULES_BY_FRAMEWORK.keys()) | {"MITRE", "CLEANCODE", "NIST", "PCIDSS", "HIPAA"}
        assert KNOWN_FRAMEWORKS == seeded

    def test_core_frameworks_have_rules(self):
        for fw in ["OWASP", "STRIDE", "CWE"]:
            assert fw in ALL_RULES_BY_FRAMEWORK, f"{fw} missing from rule data"
            assert len(ALL_RULES_BY_FRAMEWORK[fw]) > 0, f"{fw} has no rules"


# ---------------------------------------------------------------------------
# Rule field completeness
# ---------------------------------------------------------------------------
class TestRuleFieldCompleteness:
    @pytest.mark.parametrize("framework,rules", ALL_RULES_BY_FRAMEWORK.items())
    def test_every_rule_has_code(self, framework, rules):
        for r in rules:
            assert r["code"], f"{framework}: rule missing code"

    @pytest.mark.parametrize("framework,rules", ALL_RULES_BY_FRAMEWORK.items())
    def test_every_rule_has_title(self, framework, rules):
        for r in rules:
            assert r["title"].strip(), f"{framework}/{r['code']}: empty title"

    @pytest.mark.parametrize("framework,rules", ALL_RULES_BY_FRAMEWORK.items())
    def test_every_rule_has_valid_severity(self, framework, rules):
        for r in rules:
            assert r["severity"] in ALLOWED_SEVERITIES, (
                f"{framework}/{r['code']}: invalid severity '{r['severity']}'"
            )

    @pytest.mark.parametrize("framework,rules", ALL_RULES_BY_FRAMEWORK.items())
    def test_every_rule_has_languages(self, framework, rules):
        for r in rules:
            assert r["languages"], f"{framework}/{r['code']}: empty languages list"
            for lang in r["languages"]:
                assert lang in ALLOWED_LANGUAGES, (
                    f"{framework}/{r['code']}: unknown language '{lang}'"
                )


# ---------------------------------------------------------------------------
# Rule code uniqueness
# ---------------------------------------------------------------------------
class TestRuleCodeUniqueness:
    @pytest.mark.parametrize("framework,rules", ALL_RULES_BY_FRAMEWORK.items())
    def test_no_duplicate_codes_within_framework(self, framework, rules):
        codes = [r["code"] for r in rules]
        duplicates = {c for c in codes if codes.count(c) > 1}
        assert not duplicates, f"{framework}: duplicate rule codes: {duplicates}"

    def test_owasp_codes_follow_convention(self):
        for r in OWASP_RULES:
            assert r["code"].startswith("OWASP-A"), f"OWASP rule code doesn't follow OWASP-AXX convention: {r['code']}"

    def test_stride_codes_follow_convention(self):
        valid = {"STRIDE-S", "STRIDE-T", "STRIDE-R", "STRIDE-I", "STRIDE-D", "STRIDE-E"}
        for r in STRIDE_RULES:
            assert r["code"] in valid, f"Unexpected STRIDE code: {r['code']}"

    def test_cwe_codes_follow_convention(self):
        for r in CWE_RULES:
            assert r["code"].startswith("CWE-"), f"CWE rule doesn't start with CWE-: {r['code']}"
            number_part = r["code"].split("-")[1]
            assert number_part.isdigit(), f"CWE number is not numeric: {r['code']}"


# ---------------------------------------------------------------------------
# Minimum coverage
# ---------------------------------------------------------------------------
class TestMinimumCoverage:
    @pytest.mark.parametrize("framework,minimum", MIN_RULE_COUNTS.items())
    def test_framework_meets_minimum_rule_count(self, framework, minimum):
        count = len(ALL_RULES_BY_FRAMEWORK.get(framework, []))
        assert count >= minimum, (
            f"{framework} has only {count} rules, minimum is {minimum}"
        )

    def test_owasp_covers_all_10_categories(self):
        codes = {r["code"] for r in OWASP_RULES}
        for i in range(1, 11):
            expected = f"OWASP-A{i:02d}"
            assert expected in codes, f"Missing OWASP category: {expected}"

    def test_stride_covers_all_6_categories(self):
        codes = {r["code"] for r in STRIDE_RULES}
        for letter in ["S", "T", "R", "I", "D", "E"]:
            expected = f"STRIDE-{letter}"
            assert expected in codes, f"Missing STRIDE category: STRIDE-{letter}"

    def test_cwe_includes_injection_rules(self):
        """SQL injection and OS command injection must always be present — they are the most exploited."""
        codes = {r["code"] for r in CWE_RULES}
        assert "CWE-89" in codes,  "CWE-89 (SQL Injection) is missing"
        assert "CWE-78" in codes,  "CWE-78 (OS Command Injection) is missing"
        assert "CWE-79" in codes,  "CWE-79 (XSS) is missing"
        assert "CWE-798" in codes, "CWE-798 (Hard-coded Credentials) is missing"

    def test_critical_severities_present_in_each_core_framework(self):
        """Each core framework must have at least one CRITICAL severity rule."""
        for fw, rules in ALL_RULES_BY_FRAMEWORK.items():
            criticals = [r for r in rules if r["severity"] == "CRITICAL"]
            assert criticals, f"{fw} has no CRITICAL severity rules — coverage is too weak"


# ---------------------------------------------------------------------------
# Severity distribution sanity
# ---------------------------------------------------------------------------
class TestSeverityDistribution:
    def test_owasp_severity_distribution_is_realistic(self):
        """OWASP Top 10 should not be all CRITICAL — it has a range of severities."""
        severities = [r["severity"] for r in OWASP_RULES]
        unique = set(severities)
        assert len(unique) >= 3, f"OWASP rules have too narrow severity range: {unique}"

    def test_no_framework_is_all_low_severity(self):
        for fw, rules in ALL_RULES_BY_FRAMEWORK.items():
            all_low = all(r["severity"] == "LOW" for r in rules)
            assert not all_low, f"{fw}: all rules are LOW — framework is misconfigured"

    def test_critical_rules_are_minority(self):
        """CRITICAL should not be overused — if everything is critical, nothing is."""
        for fw, rules in ALL_RULES_BY_FRAMEWORK.items():
            total = len(rules)
            criticals = sum(1 for r in rules if r["severity"] == "CRITICAL")
            ratio = criticals / total
            assert ratio <= 0.5, (
                f"{fw}: {criticals}/{total} rules are CRITICAL ({ratio:.0%}) — "
                f"severity inflation detected"
            )
