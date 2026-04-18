from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.db.models import ScanHistory, Comparison, Licence, TeamPrompt


async def check_scan_quota(
    db: AsyncSession,
    licence_id: str,
    scans_per_day: Optional[int],
) -> bool:
    if scans_per_day is None:
        return True  # unlimited

    since = datetime.now(timezone.utc) - timedelta(days=1)
    result = await db.execute(
        select(func.count(ScanHistory.id)).where(
            ScanHistory.licence_id == licence_id,
            ScanHistory.created_at >= since,
        )
    )
    count = result.scalar_one()
    return count < scans_per_day


async def record_scan(
    db: AsyncSession,
    licence_id: str,
    file_name: str,
    file_hash: str,
    language: str,
    model: str,
    provider: str,
    frameworks: list[str],
    score: float,
    findings_summary: dict,
    finding_count: int,
    token_count: Optional[int],
    duration_ms: Optional[int],
    prompt_id: Optional[str],
    user_email: Optional[str] = None,
) -> ScanHistory:
    resolved_prompt_id = await _resolve_prompt_id(db, licence_id, prompt_id)

    scan = ScanHistory(
        licence_id=licence_id,
        user_email=user_email,
        file_name=file_name,
        file_hash=file_hash,
        language=language,
        model=model,
        provider=provider,
        frameworks=frameworks,
        score=score,
        findings_summary=findings_summary,
        finding_count=finding_count,
        token_count=token_count,
        duration_ms=duration_ms,
        prompt_id=resolved_prompt_id,
        status="completed",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def _resolve_prompt_id(
    db: AsyncSession,
    licence_id: str,
    prompt_id: Optional[str],
) -> Optional[str]:
    if not prompt_id:
        return None

    try:
        result = await db.execute(
            select(TeamPrompt.id).where(
                TeamPrompt.id == prompt_id,
                TeamPrompt.licence_id == licence_id,
            )
        )
        matched_prompt_id = result.scalar_one_or_none()
        return str(matched_prompt_id) if matched_prompt_id else None
    except Exception:
        return None


async def record_comparison(
    db: AsyncSession,
    licence_id: str,
    scan_a_id: str,
    scan_b_id: str,
    findings_a: list[dict],
    findings_b: list[dict],
    score_a: float,
    score_b: float,
) -> dict:
    def normalize_finding_detail(finding: dict) -> dict:
        return {
            "issue_id": finding.get("issue_id") or finding.get("canonical_id"),
            "canonical_title": finding.get("canonical_title"),
            "line": finding.get("line"),
            "framework": finding.get("framework"),
            "rule_code": finding.get("rule_code"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
        }

    # Diff algorithm:
    # 1. Canonical issue identity when present
    # 2. Fallback to line/framework/rule_code for legacy findings
    def make_key(f: dict) -> str:
        issue_id = f.get("issue_id") or f.get("canonical_id")
        if issue_id:
            return f"issue:{issue_id}:line:{f.get('line')}"
        return f"legacy:{f.get('line')}:{f.get('framework')}:{f.get('rule_code')}"

    def canonical_key(f: dict) -> str:
        return f.get("issue_id") or f.get("canonical_id") or "__unresolved__"

    def summarize_canonical(findings: list[dict]) -> dict[str, dict]:
        summary: dict[str, dict] = {}
        for finding in findings:
            key = canonical_key(finding)
            entry = summary.setdefault(
                key,
                {
                    "issue_id": None if key == "__unresolved__" else key,
                    "title": finding.get("canonical_title") or finding.get("title"),
                    "severity": finding.get("severity"),
                    "count": 0,
                    "frameworks": set(),
                },
            )
            entry["count"] += 1
            if finding.get("framework"):
                entry["frameworks"].add(finding.get("framework"))
        for entry in summary.values():
            entry["frameworks"] = sorted(entry["frameworks"])
        return summary

    keys_a = {make_key(f): f for f in findings_a}
    keys_b = {make_key(f): f for f in findings_b}

    new_findings = [f for k, f in keys_b.items() if k not in keys_a]
    resolved_findings = [f for k, f in keys_a.items() if k not in keys_b]
    agreed_findings = [f for k, f in keys_b.items() if k in keys_a]
    new_finding_details = [normalize_finding_detail(f) for f in new_findings]
    resolved_finding_details = [normalize_finding_detail(f) for f in resolved_findings]

    severity_changes = []
    for key in set(keys_a) & set(keys_b):
        if keys_a[key].get("severity") != keys_b[key].get("severity"):
            severity_changes.append({
                "finding": keys_b[key],
                "severity_a": keys_a[key].get("severity"),
                "severity_b": keys_b[key].get("severity"),
            })

    score_change = round(score_b - score_a, 2)
    if score_change > 0:
        verdict = "improved"
    elif score_change < 0:
        verdict = "regressed"
    else:
        verdict = "unchanged"

    diff_summary = {
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "agreed_count": len(agreed_findings),
        "severity_change_count": len(severity_changes),
        "verdict": verdict,
    }

    canonical_a = summarize_canonical(findings_a)
    canonical_b = summarize_canonical(findings_b)
    all_canonical_keys = sorted(set(canonical_a) | set(canonical_b))
    canonical_changes = []
    for key in all_canonical_keys:
        before = canonical_a.get(key, {"count": 0, "title": None, "severity": None, "frameworks": []})
        after = canonical_b.get(key, {"count": 0, "title": None, "severity": None, "frameworks": []})
        if before["count"] == after["count"]:
            continue
        canonical_changes.append(
            {
                "issue_id": None if key == "__unresolved__" else key,
                "title": after.get("title") or before.get("title") or "Unresolved finding",
                "severity": after.get("severity") or before.get("severity"),
                "count_a": before["count"],
                "count_b": after["count"],
                "delta": after["count"] - before["count"],
                "frameworks": sorted(set(before.get("frameworks", [])) | set(after.get("frameworks", []))),
            }
        )

    comparison = Comparison(
        licence_id=licence_id,
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        score_change=score_change,
        new_findings=len(new_findings),
        resolved_findings=len(resolved_findings),
        diff_summary=diff_summary,
    )
    db.add(comparison)
    await db.commit()
    await db.refresh(comparison)

    return {
        "comparison_id": str(comparison.id),
        "score_a": score_a,
        "score_b": score_b,
        "score_change": score_change,
        "new_findings": len(new_findings),
        "resolved_findings": len(resolved_findings),
        "agreed_findings": len(agreed_findings),
        "new_finding_details": new_finding_details,
        "resolved_finding_details": resolved_finding_details,
        "severity_changes": severity_changes,
        "canonical_changes": canonical_changes,
        "summary": {**diff_summary},
    }
