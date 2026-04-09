from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import re

from app.db.models import Framework, Rule, PromptTemplate
from app.services.knowledge_base import summarize_issues_for_prompt


async def build_prompt(
    db: AsyncSession,
    frameworks: list[str],
    language: str,
    model: str,
    severity_threshold: str = "MEDIUM",
    team_context: str = "",
    custom_prompt: Optional[str] = None,
    template_id: Optional[str] = None,
    allowed_frameworks: Optional[list[str]] = None,
) -> dict:
    # Filter to only frameworks the licence allows
    if allowed_frameworks:
        frameworks = [f for f in frameworks if f in allowed_frameworks]

    if not frameworks:
        frameworks = ["OWASP"]

    # Custom prompt bypasses template lookup
    if custom_prompt:
        assembled = _substitute_variables(
            custom_prompt, language, frameworks, severity_threshold, team_context
        )
        return {
            "system_prompt": assembled,
            "template_id": None,
            "template_name": "custom",
            "rules_loaded": 0,
            "source": "custom",
        }

    # Find the best matching template
    template = await _find_template(db, template_id, frameworks, language)

    if not template:
        # Fallback: minimal hardcoded prompt
        return _hardcoded_fallback(frameworks, language, severity_threshold, team_context)

    # Load rules for the selected frameworks
    rules = await _load_rules(db, frameworks, language, severity_threshold)

    # Assemble: substitute variables in template
    assembled = _substitute_variables(
        template.template, language, frameworks, severity_threshold, team_context
    )

    # Append rule hints if template has a {rules} placeholder
    if "{rules}" in assembled and rules:
        rule_text = _format_rules(rules)
        assembled = assembled.replace("{rules}", rule_text)

    assembled += "\n\n" + _canonical_resolution_guidance()

    return {
        "system_prompt": assembled,
        "template_id": str(template.id),
        "template_name": template.name,
        "rules_loaded": len(rules),
        "source": "template",
    }


async def _find_template(
    db: AsyncSession,
    template_id: Optional[str],
    frameworks: list[str],
    language: str,
) -> Optional[PromptTemplate]:
    if template_id:
        result = await db.execute(
            select(PromptTemplate).where(
                PromptTemplate.id == template_id,
                PromptTemplate.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    # Find baseline template for the primary framework
    primary = frameworks[0] if frameworks else "OWASP"
    result = await db.execute(
        select(PromptTemplate)
        .join(Framework, PromptTemplate.framework_id == Framework.id)
        .where(
            Framework.code == primary,
            PromptTemplate.is_baseline == True,
            PromptTemplate.is_active == True,
        )
        .order_by(PromptTemplate.version.desc())
        .limit(1)
    )
    template = result.scalar_one_or_none()

    # Fall back to any active baseline
    if not template:
        result = await db.execute(
            select(PromptTemplate)
            .where(
                PromptTemplate.is_baseline == True,
                PromptTemplate.is_active == True,
            )
            .limit(1)
        )
        template = result.scalar_one_or_none()

    return template


async def _load_rules(
    db: AsyncSession,
    frameworks: list[str],
    language: str,
    severity_threshold: str,
) -> list[Rule]:
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_severity = severity_order.get(severity_threshold.upper(), 1)

    result = await db.execute(
        select(Rule)
        .join(Framework, Rule.framework_id == Framework.id)
        .where(
            Framework.code.in_(frameworks),
            Rule.is_active == True,
        )
    )
    rules = result.scalars().all()

    # Filter by severity and language
    filtered = []
    for rule in rules:
        rule_sev = severity_order.get(rule.severity.upper(), 0)
        if rule_sev < min_severity:
            continue
        if rule.languages and language.lower() not in [l.lower() for l in rule.languages]:
            if "all" not in [l.lower() for l in rule.languages]:
                continue
        filtered.append(rule)

    return filtered


def _format_rules(rules: list[Rule]) -> str:
    lines = []
    for r in rules:
        hint = f"- [{r.code}] {r.title} ({r.severity})"
        if r.prompt_hints:
            hint += f": {r.prompt_hints}"
        lines.append(hint)
    return "\n".join(lines)


def _substitute_variables(
    template: str,
    language: str,
    frameworks: list[str],
    severity_threshold: str,
    team_context: str,
) -> str:
    result = template
    result = result.replace("{language}", language)
    result = result.replace("{frameworks}", ", ".join(frameworks))
    result = result.replace("{severity_threshold}", severity_threshold)
    result = result.replace("{team_context}", team_context or "")
    return result


def _hardcoded_fallback(
    frameworks: list[str],
    language: str,
    severity_threshold: str,
    team_context: str,
) -> dict:
    prompt = f"""You are a senior security engineer conducting a formal code review.

Analyse the following {language} code for security vulnerabilities using {", ".join(frameworks)}.
Report only {severity_threshold} severity and above.
{team_context}

Resolve each finding to the closest Owlvex canonical issue when possible.

Known canonical issues:
{summarize_issues_for_prompt()}

Return ONLY valid JSON:
{{
  "score": <float 0-10>,
  "summary": "<one sentence>",
  "findings": [{{"id":"<uuid>","line":<int>,"line_end":<int>,"severity":"<CRITICAL|HIGH|MEDIUM|LOW>","framework":"<fw>","rule_code":"<code>","title":"<title>","explanation":"<why>","threat":"<impact>","fix":"<fix>","confidence":<float>,"issue_id":"<owlvex.issue... optional>","stride":["<STRIDE category>"],"mappings":{{"cwe":["<id>"],"owasp":["<id>"],"api_owasp":["<id>"],"attack":["<id>"],"capec":["<id>"],"nist":["<id>"]}},"matched_signals":["<why it matched>"]}}],
  "positives": ["<strength>"],
  "metrics": {{"critical":<int>,"high":<int>,"medium":<int>,"low":<int>}}
}}"""
    return {
        "system_prompt": prompt,
        "template_id": None,
        "template_name": "fallback",
        "rules_loaded": 0,
        "source": "fallback",
    }


def _canonical_resolution_guidance() -> str:
    return (
        "Owlvex canonical resolution guidance:\n"
        "1. Prefer returning issue_id for the closest canonical Owlvex issue.\n"
        "2. Include stride, mappings, and matched_signals whenever the match is clear.\n"
        "3. If uncertain, keep rule_code/framework accurate and omit issue_id rather than guessing."
    )
