import { CanonicalIssue, CanonicalMappings, ISSUE_CATALOG } from './issueCatalog';

interface RulePackIssueArtifact {
    issues?: Array<Record<string, unknown>>;
}

interface RulePackMappingArtifact {
    mappings?: Array<{
        issue_id?: string;
        framework_mappings?: Array<{
            framework_code?: string;
            external_id?: string;
        }>;
    }>;
}

export interface DynamicFrameworkMappingMatch {
    issue: CanonicalIssue;
    matchedSignals: string[];
}

let effectiveCatalog: CanonicalIssue[] = ISSUE_CATALOG;
let effectiveIssueIndex: Map<string, CanonicalIssue> = new Map(ISSUE_CATALOG.map(issue => [issue.id, issue]));
let dynamicMappingIndex: Map<string, DynamicFrameworkMappingMatch> = new Map();

function normalizeStringList(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .map(item => String(item).trim())
        .filter(Boolean);
}

function normalizeMappings(value: unknown): CanonicalMappings {
    const raw = (value && typeof value === 'object') ? value as Record<string, unknown> : {};
    return {
        cwe: normalizeStringList(raw.cwe),
        owasp: normalizeStringList(raw.owasp),
        apiOwasp: normalizeStringList(raw.api_owasp ?? raw.apiOwasp),
        attack: normalizeStringList(raw.attack),
        capec: normalizeStringList(raw.capec),
        nist: normalizeStringList(raw.nist),
    };
}

function normalizeSeverity(value: unknown): CanonicalIssue['severity'] {
    const normalized = String(value ?? '').trim().toUpperCase();
    if (normalized === 'CRITICAL' || normalized === 'HIGH' || normalized === 'MEDIUM' || normalized === 'LOW' || normalized === 'INFO') {
        return normalized;
    }
    return 'MEDIUM';
}

function normalizeDetectionLevel(value: unknown): CanonicalIssue['detectionLevel'] {
    const normalized = String(value ?? '').trim().toLowerCase();
    if (normalized === 'direct' || normalized === 'flow' || normalized === 'inferred' || normalized === 'partial') {
        return normalized;
    }
    return 'direct';
}

function buildDynamicIssueOverlay(rawIssue: Record<string, unknown>): Partial<CanonicalIssue> | undefined {
    const id = String(rawIssue.id ?? '').trim();
    if (!id) {
        return undefined;
    }

    const detection = (rawIssue.detection && typeof rawIssue.detection === 'object')
        ? rawIssue.detection as Record<string, unknown>
        : {};
    const remediation = (rawIssue.remediation && typeof rawIssue.remediation === 'object')
        ? rawIssue.remediation as Record<string, unknown>
        : {};

    return {
        id,
        slug: String(rawIssue.slug ?? id).trim(),
        title: String(rawIssue.title ?? rawIssue.summary ?? id).trim(),
        category: String(rawIssue.category ?? 'security').trim(),
        family: String(rawIssue.family ?? 'family.security_misconfiguration').trim(),
        severity: normalizeSeverity(rawIssue.severity),
        stride: normalizeStringList(rawIssue.stride),
        mappings: normalizeMappings(rawIssue.mappings),
        keywords: normalizeStringList(detection.patterns ?? rawIssue.tags),
        remediationSummary: String(remediation.summary ?? rawIssue.summary ?? '').trim(),
        cheatSheetRefs: normalizeStringList(remediation.cheat_sheet_refs),
        detectionLevel: normalizeDetectionLevel(rawIssue.detection_level),
        requiresTrustTracking: Boolean(rawIssue.requires_trust_tracking),
        applicability: String(rawIssue.applicability ?? 'global').trim() === 'conditional' ? 'conditional' : 'global',
        requires: normalizeStringList(rawIssue.requires),
    };
}

function mappingKey(frameworkCode: string, externalId: string): string {
    return `${frameworkCode.trim().toUpperCase()}::${externalId.trim().toUpperCase()}`;
}

export function configureRulePackRuntime(
    issueArtifact?: Record<string, unknown>,
    mappingArtifact?: Record<string, unknown>,
): void {
    const issuePack = issueArtifact as RulePackIssueArtifact | undefined;
    const mappingPack = mappingArtifact as RulePackMappingArtifact | undefined;

    const dynamicIssues = new Map<string, Partial<CanonicalIssue>>();
    for (const rawIssue of issuePack?.issues ?? []) {
        const overlay = buildDynamicIssueOverlay(rawIssue);
        if (overlay?.id) {
            dynamicIssues.set(overlay.id, overlay);
        }
    }

    effectiveCatalog = ISSUE_CATALOG.map(issue => ({
        ...issue,
        ...(dynamicIssues.get(issue.id) ?? {}),
        mappings: dynamicIssues.get(issue.id)?.mappings ?? issue.mappings,
        stride: dynamicIssues.get(issue.id)?.stride?.length ? dynamicIssues.get(issue.id)!.stride! : issue.stride,
        keywords: dynamicIssues.get(issue.id)?.keywords?.length ? dynamicIssues.get(issue.id)!.keywords! : issue.keywords,
        cheatSheetRefs: dynamicIssues.get(issue.id)?.cheatSheetRefs?.length ? dynamicIssues.get(issue.id)!.cheatSheetRefs! : issue.cheatSheetRefs,
        remediationSummary: dynamicIssues.get(issue.id)?.remediationSummary || issue.remediationSummary,
        requires: dynamicIssues.get(issue.id)?.requires?.length ? dynamicIssues.get(issue.id)!.requires : issue.requires,
    }));

    for (const [id, overlay] of dynamicIssues.entries()) {
        if (!effectiveCatalog.some(issue => issue.id === id)) {
            effectiveCatalog.push({
                id,
                slug: overlay.slug ?? id,
                title: overlay.title ?? id,
                category: overlay.category ?? 'security',
                family: overlay.family ?? 'family.security_misconfiguration',
                severity: overlay.severity ?? 'MEDIUM',
                stride: overlay.stride ?? [],
                mappings: overlay.mappings ?? {
                    cwe: [],
                    owasp: [],
                    apiOwasp: [],
                    attack: [],
                    capec: [],
                    nist: [],
                },
                keywords: overlay.keywords ?? [],
                remediationSummary: overlay.remediationSummary ?? '',
                cheatSheetRefs: overlay.cheatSheetRefs ?? [],
                detectionLevel: overlay.detectionLevel ?? 'direct',
                requiresTrustTracking: overlay.requiresTrustTracking ?? false,
                applicability: overlay.applicability ?? 'global',
                requires: overlay.requires,
            });
        }
    }

    effectiveIssueIndex = new Map(effectiveCatalog.map(issue => [issue.id, issue]));
    dynamicMappingIndex = new Map();

    for (const mapping of mappingPack?.mappings ?? []) {
        const issueId = String(mapping.issue_id ?? '').trim();
        if (!issueId) {
            continue;
        }

        const issue = effectiveIssueIndex.get(issueId);
        if (!issue) {
            continue;
        }

        for (const frameworkMapping of mapping.framework_mappings ?? []) {
            const frameworkCode = String(frameworkMapping.framework_code ?? '').trim().toUpperCase();
            const externalId = String(frameworkMapping.external_id ?? '').trim().toUpperCase();
            if (!frameworkCode || !externalId) {
                continue;
            }

            dynamicMappingIndex.set(mappingKey(frameworkCode, externalId), {
                issue,
                matchedSignals: [`${frameworkCode}:${externalId}`],
            });
        }
    }
}

export function resetRulePackRuntime(): void {
    effectiveCatalog = ISSUE_CATALOG;
    effectiveIssueIndex = new Map(ISSUE_CATALOG.map(issue => [issue.id, issue]));
    dynamicMappingIndex = new Map();
}

export function getEffectiveIssueCatalog(): CanonicalIssue[] {
    return effectiveCatalog;
}

export function getEffectiveCanonicalIssueById(id: string): CanonicalIssue | undefined {
    return effectiveIssueIndex.get(id);
}

export function findDynamicFrameworkMapping(framework: string, ruleCode: string): DynamicFrameworkMappingMatch | undefined {
    if (!framework.trim() || !ruleCode.trim()) {
        return undefined;
    }

    return dynamicMappingIndex.get(mappingKey(framework, ruleCode));
}
