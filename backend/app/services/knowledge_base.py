from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_json(relative_path: str) -> dict[str, Any]:
    path = _repo_root() / relative_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def load_issue_pack() -> dict[str, Any]:
    return _load_json("docs/data/issues/owlvex-issue-pack.v1.json")


@lru_cache(maxsize=1)
def load_issue_mapping_pack() -> dict[str, Any]:
    return _load_json("docs/data/issues/owlvex-issue-mappings.v1.json")


@lru_cache(maxsize=1)
def load_stride_profile() -> dict[str, Any]:
    return _load_json("docs/data/stride/owlvex.stride.2026.1.json")


@lru_cache(maxsize=1)
def get_canonical_issues() -> list[dict[str, Any]]:
    return load_issue_pack().get("issues", [])


@lru_cache(maxsize=1)
def get_canonical_issue_index() -> dict[str, dict[str, Any]]:
    return {issue["id"]: issue for issue in get_canonical_issues()}


def get_canonical_issue(issue_id: str) -> dict[str, Any] | None:
    return get_canonical_issue_index().get(issue_id)


def get_framework_issue_index() -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    issues = get_canonical_issue_index()
    mapping_pack = load_issue_mapping_pack()

    for item in mapping_pack.get("mappings", []):
        issue = issues.get(item.get("issue_id"))
        if not issue:
            continue
        for mapping in item.get("framework_mappings", []):
            framework_code = str(mapping.get("framework_code", "")).upper()
            external_id = str(mapping.get("external_id", "")).upper()
            if framework_code and external_id:
                index[(framework_code, external_id)] = issue

    return index


def summarize_issues_for_prompt(limit: int = 10) -> str:
    issues = get_canonical_issues()[:limit]
    lines: list[str] = []
    for issue in issues:
        mappings = issue.get("mappings", {})
        cwe = ", ".join(mappings.get("cwe", [])) or "n/a"
        owasp = ", ".join(mappings.get("owasp", [])) or "n/a"
        stride = ", ".join(issue.get("stride", [])) or "n/a"
        lines.append(
            f"- {issue['id']}: {issue['title']} | severity={issue['severity']} | CWE={cwe} | OWASP={owasp} | STRIDE={stride}"
        )
    return "\n".join(lines)
