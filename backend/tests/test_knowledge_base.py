from app.services.knowledge_base import (
    get_canonical_issue,
    get_canonical_issues,
    get_framework_issue_index,
    summarize_issues_for_prompt,
)


def test_loads_canonical_issues():
    issues = get_canonical_issues()
    assert len(issues) >= 10
    assert any(issue["id"] == "owlvex.issue.sql_injection.001" for issue in issues)


def test_lookup_by_issue_id():
    issue = get_canonical_issue("owlvex.issue.command_injection.001")
    assert issue is not None
    assert issue["title"] == "Unsafe shell command execution"


def test_framework_index_maps_cwe_to_issue():
    index = get_framework_issue_index()
    issue = index.get(("CWE", "CWE-78"))
    assert issue is not None
    assert issue["id"] == "owlvex.issue.command_injection.001"


def test_prompt_summary_contains_canonical_ids():
    summary = summarize_issues_for_prompt(limit=2)
    assert "owlvex.issue.sql_injection.001" in summary
