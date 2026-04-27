import * as fs from 'node:fs';
import { getIssueFamilyDefinition } from './issueCatalog';
import { getGroundedCheatSheetGuidanceForIssueIds } from './remediationResolver';
import { getEffectiveIssueCatalog } from './rulePackRegistry';
import { resolveRuntimeDataPath } from './runtimeDataPath';
import { getOwaspFrameworkDetails, OWASP_2025_CATEGORIES } from './owaspProfile';

interface FrameworkPackFramework {
    code: string;
    name: string;
    version: string;
    description: string;
    owlvex_profile_id?: string;
}

interface FrameworkPackProfile {
    id: string;
    framework_code: string;
    title: string;
    purpose: string;
    prompt_guidance?: string[];
    report_focus?: string[];
    allowed_mapping_fields?: string[];
    ai_usage_rules?: string[];
}

interface FrameworkPack {
    frameworks?: FrameworkPackFramework[];
    profiles?: FrameworkPackProfile[];
}

let cachedFrameworkPack: FrameworkPack | undefined;
let runtimeFrameworkPack: FrameworkPack | undefined;

function normalizeFrameworkCode(value: string | undefined): string {
    return String(value ?? '').replace(/[^a-z0-9]/gi, '').toUpperCase();
}

function loadFrameworkPack(): FrameworkPack {
    if (runtimeFrameworkPack) {
        return runtimeFrameworkPack;
    }

    if (cachedFrameworkPack) {
        return cachedFrameworkPack;
    }

    const raw = fs.readFileSync(
        resolveRuntimeDataPath(__dirname, 'frameworks', 'owlvex.framework-pack.2026.1.json'),
        'utf8',
    );
    cachedFrameworkPack = JSON.parse(raw) as FrameworkPack;
    return cachedFrameworkPack;
}

export function configureFrameworkPackRuntime(artifact?: Record<string, unknown>): void {
    runtimeFrameworkPack = artifact as FrameworkPack | undefined;
}

export function getGroundedFrameworkLabels(selectedFrameworks: string[]): string[] {
    if (!selectedFrameworks.length) {
        return [];
    }

    const frameworkPack = loadFrameworkPack();
    const selectedCodes = [...new Set(selectedFrameworks.map(normalizeFrameworkCode).filter(Boolean))];

    return selectedCodes.map(code => {
        const framework = frameworkPack.frameworks?.find(entry => normalizeFrameworkCode(entry.code) === code);
        return framework?.name ?? code;
    });
}

function issueMatchesFrameworkScope(issue: { mappings: { cwe: string[]; owasp: string[]; apiOwasp: string[]; attack: string[]; capec: string[]; nist: string[] }; stride: string[] }, selectedCodes: string[]): boolean {
    if (!selectedCodes.length) {
        return true;
    }

    return selectedCodes.some(code => {
        switch (code) {
            case 'OWASP':
                return issue.mappings.owasp.length > 0 || issue.mappings.apiOwasp.length > 0;
            case 'CWE':
                return issue.mappings.cwe.length > 0;
            case 'MITRE':
                return issue.mappings.attack.length > 0 || issue.mappings.capec.length > 0;
            case 'NIST':
                return issue.mappings.nist.length > 0;
            case 'STRIDE':
                return issue.stride.length > 0;
            default:
                return false;
        }
    });
}

function scoreIssueCandidate(haystack: string, issue: { keywords: string[]; requiredAnyKeywords?: string[]; negativeKeywords?: string[] }): { score: number; matches: string[] } {
    const matches = issue.keywords
        .filter(keyword => haystack.includes(keyword.toLowerCase()))
        .slice(0, 4);

    if (!matches.length) {
        return { score: 0, matches: [] };
    }

    if (issue.requiredAnyKeywords?.length && !issue.requiredAnyKeywords.some(keyword => haystack.includes(keyword.toLowerCase()))) {
        return { score: 0, matches: [] };
    }

    const negativeHits = (issue.negativeKeywords ?? [])
        .filter(keyword => haystack.includes(keyword.toLowerCase()));

    const score = (matches.length * 12) - (negativeHits.length * 8);
    return {
        score: Math.max(0, score),
        matches,
    };
}

export function buildAiIssueGroundingPromptContext(
    code: string,
    selectedFrameworks: string[],
    existingIssueIds: string[],
): string {
    const haystack = code.toLowerCase();
    const selectedCodes = [...new Set(selectedFrameworks.map(normalizeFrameworkCode).filter(Boolean))];
    const existingIds = new Set(existingIssueIds);

    const candidates = getEffectiveIssueCatalog()
        .filter(issue => !existingIds.has(issue.id))
        .filter(issue => issueMatchesFrameworkScope(issue, selectedCodes))
        .map(issue => {
            const { score, matches } = scoreIssueCandidate(haystack, issue);
            return { issue, score, matches };
        })
        .filter(item => item.score >= 12)
        .sort((left, right) => right.score - left.score || left.issue.title.localeCompare(right.issue.title))
        .slice(0, 3);

    if (!candidates.length) {
        return '';
    }

    return [
        'Grounded candidate issues for AI-only analysis:',
        'Use these as bounded candidates when the code suggests an uncovered class. Prefer these canonical issues over inventing a new label when the evidence fits.',
        ...candidates.map((item, index) => {
            const family = getIssueFamilyDefinition(item.issue.family)?.label ?? item.issue.family;
            const cheatSheets = getGroundedCheatSheetGuidanceForIssueIds([item.issue.id]).slice(0, 1);
            const cheatSheetLine = cheatSheets.length
                ? `Cheat-sheet guidance: ${cheatSheets.map(entry => {
                    const actions = (entry.common_actions ?? []).slice(0, 2).join(' | ');
                    return `${entry.label}${entry.focus ? ` (${entry.focus})` : ''}${actions ? ` | Actions: ${actions}` : ''}`;
                }).join(' || ')}`
                : '';

            return [
                `${index + 1}. ${item.issue.id} | ${item.issue.title}`,
                `Family: ${family}`,
                `Signals matched in code: ${item.matches.join(', ')}`,
                `Remediation baseline: ${item.issue.remediationSummary}`,
                cheatSheetLine,
            ].filter(Boolean).join('\n');
        }),
    ].join('\n\n');
}

export function buildGroundedFrameworkPromptContext(selectedFrameworks: string[]): string {
    if (!selectedFrameworks.length) {
        return '';
    }

    const frameworkPack = loadFrameworkPack();
    const selectedCodes = [...new Set(selectedFrameworks.map(normalizeFrameworkCode).filter(Boolean))];
    const sections = selectedCodes.map(code => {
        const framework = frameworkPack.frameworks?.find(entry => normalizeFrameworkCode(entry.code) === code);
        const profile = frameworkPack.profiles?.find(entry => normalizeFrameworkCode(entry.framework_code) === code);
        if (!framework && !profile) {
            return '';
        }
        const owaspDetails = code === 'OWASP' ? getOwaspFrameworkDetails() : undefined;
        const owaspCategories = code === 'OWASP' && owaspDetails?.version === '2025'
            ? `OWASP 2025 categories: ${OWASP_2025_CATEGORIES.join(' | ')}`
            : '';

        return [
            `${code}: ${(framework?.name ?? profile?.title ?? code)}${framework?.version ? ` (${framework.version})` : owaspDetails?.version ? ` (${owaspDetails.version})` : ''}`,
            framework?.description ? `Description: ${framework.description}` : owaspDetails?.description ? `Description: ${owaspDetails.description}` : '',
            profile?.purpose ? `Purpose: ${profile.purpose}` : '',
            profile?.prompt_guidance?.length ? `Prompt guidance: ${profile.prompt_guidance.slice(0, 3).join(' | ')}` : owaspDetails?.promptGuidance.length ? `Prompt guidance: ${owaspDetails.promptGuidance.join(' | ')}` : '',
            profile?.report_focus?.length ? `Report focus: ${profile.report_focus.slice(0, 3).join(' | ')}` : owaspDetails?.reportFocus.length ? `Report focus: ${owaspDetails.reportFocus.join(' | ')}` : '',
            owaspCategories,
            profile?.allowed_mapping_fields?.length ? `Allowed mapping fields: ${profile.allowed_mapping_fields.join(', ')}` : '',
            profile?.ai_usage_rules?.length ? `AI rules: ${profile.ai_usage_rules.slice(0, 2).join(' | ')}` : '',
        ].filter(Boolean).join('\n');
    }).filter(Boolean);

    if (!sections.length) {
        return '';
    }

    return [
        'Grounded framework guidance:',
        `Selected frameworks for this scan: ${selectedCodes.join(', ')}`,
        'Only emit framework-specific mappings or vocabulary when they are in scope and supported by code evidence.',
        sections.join('\n\n'),
    ].join('\n');
}
