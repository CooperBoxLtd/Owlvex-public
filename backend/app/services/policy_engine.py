from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(str(value or "").upper(), -1)


def evaluate_policy(
    findings: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = policy or {}
    conditions = policy.get("conditions", {})
    blocked_issue_ids = set(conditions.get("issue_ids", []))
    blocked_severities = {str(item).upper() for item in conditions.get("severity", [])}
    min_severity = str(conditions.get("minimum_severity", "")).upper()
    action = str(policy.get("policy", "warn")).lower()

    matches: list[dict[str, Any]] = []
    for finding in findings:
        issue_id = finding.get("issue_id") or finding.get("canonical_id")
        severity = str(finding.get("severity", "")).upper()

        issue_match = not blocked_issue_ids or issue_id in blocked_issue_ids
        severity_match = True

        if blocked_severities:
            severity_match = severity in blocked_severities
        elif min_severity:
            severity_match = _severity_rank(severity) >= _severity_rank(min_severity)

        if issue_match and severity_match:
            matches.append(
                {
                    "issue_id": issue_id,
                    "severity": severity,
                    "title": finding.get("title"),
                    "line": finding.get("line"),
                }
            )

    final_action = "allow"
    if matches:
        if action == "block":
            final_action = "block"
        elif action == "warn":
            final_action = "warn"
        else:
            final_action = action

    return {
        "decision": final_action,
        "matched_count": len(matches),
        "matches": matches,
        "policy": {
            "policy": action,
            "conditions": conditions,
        },
    }
