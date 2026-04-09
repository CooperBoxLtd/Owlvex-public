from app.services.policy_engine import evaluate_policy


def test_policy_blocks_matching_issue_id_and_severity():
    result = evaluate_policy(
        findings=[
            {
                "issue_id": "owlvex.issue.sql_injection.001",
                "severity": "HIGH",
                "title": "SQL Injection",
                "line": 12,
            }
        ],
        policy={
            "policy": "block",
            "conditions": {
                "issue_ids": ["owlvex.issue.sql_injection.001"],
                "severity": ["HIGH", "CRITICAL"],
            },
        },
    )

    assert result["decision"] == "block"
    assert result["matched_count"] == 1


def test_policy_allows_when_nothing_matches():
    result = evaluate_policy(
        findings=[
            {
                "issue_id": "owlvex.issue.sensitive_logging.001",
                "severity": "MEDIUM",
            }
        ],
        policy={
            "policy": "block",
            "conditions": {
                "issue_ids": ["owlvex.issue.command_injection.001"],
                "severity": ["CRITICAL"],
            },
        },
    )

    assert result["decision"] == "allow"
    assert result["matched_count"] == 0


def test_policy_supports_minimum_severity():
    result = evaluate_policy(
        findings=[
            {"issue_id": "owlvex.issue.command_injection.001", "severity": "CRITICAL"},
            {"issue_id": "owlvex.issue.weak_auth_policy.001", "severity": "MEDIUM"},
        ],
        policy={
            "policy": "warn",
            "conditions": {
                "minimum_severity": "HIGH",
            },
        },
    )

    assert result["decision"] == "warn"
    assert result["matched_count"] == 1
    assert result["matches"][0]["issue_id"] == "owlvex.issue.command_injection.001"
