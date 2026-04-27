import { CanonicalIssue, CanonicalMappings } from './issueCatalog';
import {
    findDynamicFrameworkMapping,
    getEffectiveCanonicalIssueById,
    getEffectiveIssueCatalog,
} from './rulePackRegistry';
import { getOwaspMappingAliasesForActiveProfile } from './owaspProfile';
export type { CanonicalIssue, CanonicalMappings } from './issueCatalog';

export interface RawFindingLike {
    title: string;
    explanation: string;
    threat: string;
    fix: string;
    framework: string;
    ruleCode: string;
    severity: string;
}

export interface ResolvedIssue {
    issue: CanonicalIssue;
    confidence: number;
    matchedSignals: string[];
}

function normalizedMappings(issue: CanonicalIssue): Array<[string, string]> {
    return [
        ...issue.mappings.cwe.map(value => ['CWE', value] as [string, string]),
        ...issue.mappings.owasp.flatMap(value => getOwaspMappingAliasesForActiveProfile(value).map(alias => ['OWASP', alias] as [string, string])),
        ...issue.mappings.apiOwasp.map(value => ['APIOWASP', value] as [string, string]),
        ...issue.mappings.attack.map(value => ['ATTACK', value] as [string, string]),
        ...issue.mappings.capec.map(value => ['CAPEC', value] as [string, string]),
        ...issue.mappings.nist.map(value => ['NIST', value] as [string, string]),
    ];
}

function normalizeFramework(value: string): string {
    return value.replace(/[^A-Z]/gi, '').toUpperCase();
}

function normalizeRuleCode(value: string): string {
    return value.trim().toUpperCase();
}

function buildFindingHaystack(finding: RawFindingLike): string {
    return [
        finding.title,
        finding.explanation,
        finding.threat,
        finding.fix,
        finding.framework,
        finding.ruleCode,
    ].join(' ').toLowerCase();
}

export function getCanonicalIssueById(id: string): CanonicalIssue | undefined {
    return getEffectiveCanonicalIssueById(id);
}

export function resolveIssue(finding: RawFindingLike): ResolvedIssue | undefined {
    const haystack = buildFindingHaystack(finding);
    const normalizedFramework = normalizeFramework(finding.framework);
    const normalizedCode = normalizeRuleCode(finding.ruleCode);
    const dynamicExactMatch = findDynamicFrameworkMapping(normalizedFramework, normalizedCode);

    if (dynamicExactMatch) {
        return {
            issue: dynamicExactMatch.issue,
            confidence: 0.99,
            matchedSignals: dynamicExactMatch.matchedSignals,
        };
    }

    let bestMatch: ResolvedIssue | undefined;
    let bestScore = 0;
    const issueCatalog = getEffectiveIssueCatalog();

    for (const issue of issueCatalog) {
        let score = 0;
        const matchedSignals: string[] = [];

        for (const [frameworkCode, externalId] of normalizedMappings(issue)) {
            if (normalizedCode && normalizeRuleCode(externalId) === normalizedCode) {
                score += frameworkCode === normalizedFramework ? 120 : 100;
                matchedSignals.push(`${frameworkCode}:${externalId}`);
            }
        }

        for (const keyword of issue.keywords) {
            if (haystack.includes(keyword.toLowerCase())) {
                score += 15;
                matchedSignals.push(keyword);
            }
        }

        const requiredKeywordHit = !issue.requiredAnyKeywords?.length
            || issue.requiredAnyKeywords.some(keyword => haystack.includes(keyword.toLowerCase()));
        if (!requiredKeywordHit) {
            score -= 80;
        }

        for (const keyword of issue.negativeKeywords ?? []) {
            if (haystack.includes(keyword.toLowerCase())) {
                score -= 35;
                matchedSignals.push(`NEG:${keyword}`);
            }
        }

        if (finding.severity.toUpperCase() === issue.severity) {
            score += 5;
        }

        if (score > bestScore) {
            bestScore = score;
            bestMatch = {
                issue,
                confidence: Math.min(0.99, 0.45 + score / 150),
                matchedSignals: [...new Set(matchedSignals)],
            };
        }
    }

    if (!bestMatch) {
        return undefined;
    }

    return bestScore >= (bestMatch.issue.minimumScore ?? 25) ? bestMatch : undefined;
}
