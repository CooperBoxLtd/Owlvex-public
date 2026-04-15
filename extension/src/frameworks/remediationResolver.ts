import type { Finding } from '../scanner/scanEngine';
import { getCanonicalIssueById } from './issueResolver';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
    CanonicalRemediation,
    RemediationFrameworkVariant,
    getEffectiveRemediationByIssueId,
    getEffectiveRemediationCatalog,
} from './rulePackRegistry';

export interface ResolvedRemediation {
    remediation: string;
    refs: string[];
    modelNote?: string;
    frameworkVariant?: RemediationFrameworkVariant;
    validationSteps: string[];
    unsafeAlternatives: string[];
}

interface CuratedCheatSheetEntry {
    label: string;
    focus?: string;
    common_actions?: string[];
    avoid?: string[];
    issue_ids?: string[];
    remediation_entry_ids?: string[];
}

interface CuratedCheatSheetPack {
    entries?: CuratedCheatSheetEntry[];
}

let cachedCheatSheetPack: CuratedCheatSheetPack | undefined;

function normalizeFramework(value: string | undefined): string {
    return String(value ?? '').replace(/[^a-z0-9]/gi, '').toUpperCase();
}

function repoDocsPath(...segments: string[]): string {
    return path.resolve(__dirname, '../../../docs', ...segments);
}

function loadCuratedCheatSheetPack(): CuratedCheatSheetPack {
    if (cachedCheatSheetPack) {
        return cachedCheatSheetPack;
    }

    const raw = fs.readFileSync(
        repoDocsPath('data', 'cheatsheets', 'owlvex.owasp-cheatsheets.2026.1.json'),
        'utf8',
    );
    cachedCheatSheetPack = JSON.parse(raw) as CuratedCheatSheetPack;
    return cachedCheatSheetPack;
}

function getCuratedCheatSheetEntries(labels: string[]): CuratedCheatSheetEntry[] {
    if (!labels.length) {
        return [];
    }

    const wanted = new Set(labels);
    return (loadCuratedCheatSheetPack().entries ?? [])
        .filter(entry => wanted.has(entry.label));
}

export function getGroundedCheatSheetLabelsForIssueIds(issueIds: string[]): string[] {
    if (!issueIds.length) {
        return [];
    }

    const entries = getEffectiveRemediationCatalog()
        .filter(entry => issueIds.includes(entry.issueId));
    const labels = entries.flatMap(entry => entry.references.map(reference => reference.label));
    return getCuratedCheatSheetEntries(labels).map(entry => entry.label);
}

export function getGroundedCheatSheetGuidanceForIssueIds(issueIds: string[]): CuratedCheatSheetEntry[] {
    if (!issueIds.length) {
        return [];
    }

    const entries = getEffectiveRemediationCatalog()
        .filter(entry => issueIds.includes(entry.issueId));
    const labels = entries.flatMap(entry => entry.references.map(reference => reference.label));
    return getCuratedCheatSheetEntries(labels);
}

export function getCanonicalRemediationByIssueId(issueId: string): CanonicalRemediation | undefined {
    return getEffectiveRemediationByIssueId(issueId);
}

export function selectFrameworkVariant(
    remediation: CanonicalRemediation | undefined,
    frameworkHint?: string,
): RemediationFrameworkVariant | undefined {
    if (!remediation || !frameworkHint) {
        return undefined;
    }

    const normalizedHint = normalizeFramework(frameworkHint);
    return remediation.frameworkVariants.find(variant => normalizeFramework(variant.framework) === normalizedHint);
}

export function resolveRemediationForFinding(finding: Finding): ResolvedRemediation {
    const packRemediation = finding.canonicalId ? getCanonicalRemediationByIssueId(finding.canonicalId) : undefined;
    const canonicalIssue = finding.canonicalId ? getCanonicalIssueById(finding.canonicalId) : undefined;
    const frameworkVariant = selectFrameworkVariant(packRemediation, finding.framework);
    const groundedSummary = frameworkVariant?.summary
        ?? packRemediation?.canonicalFixSummary
        ?? canonicalIssue?.remediationSummary
        ?? '';
    const refs = packRemediation?.references.map(reference => reference.label)
        ?? canonicalIssue?.cheatSheetRefs
        ?? [];
    const modelFix = finding.fix?.trim();

    if (!groundedSummary) {
        return {
            remediation: modelFix || 'No fix returned.',
            refs: [],
            validationSteps: [],
            unsafeAlternatives: [],
        };
    }

    return {
        remediation: groundedSummary,
        refs,
        modelNote: !modelFix || modelFix === groundedSummary ? undefined : modelFix,
        frameworkVariant,
        validationSteps: packRemediation?.validationSteps ?? [],
        unsafeAlternatives: packRemediation?.unsafeAlternatives ?? [],
    };
}

export function buildGroundedRemediationPromptContext(issueIds?: string[]): string {
    const entries = getEffectiveRemediationCatalog();
    const filteredEntries = issueIds?.length
        ? entries.filter(entry => issueIds.includes(entry.issueId))
        : [];

    if (!filteredEntries.length) {
        return '';
    }

    return filteredEntries.map(entry => {
        const variantPreview = entry.frameworkVariants
            .slice(0, 3)
            .map(variant => `${variant.framework}: ${variant.summary}`)
            .join(' | ');
        const validationPreview = entry.validationSteps.slice(0, 2).join(' ; ');
        const unsafePreview = entry.unsafeAlternatives.slice(0, 2).join(' ; ');
        const cheatSheetPreview = getCuratedCheatSheetEntries(entry.references.map(reference => reference.label))
            .slice(0, 2)
            .map(reference => {
                const actions = (reference.common_actions ?? []).slice(0, 2).join(' ; ');
                const avoid = (reference.avoid ?? []).slice(0, 1).join(' ; ');
                return [
                    `${reference.label}: ${reference.focus ?? ''}`.trim(),
                    actions ? `Actions: ${actions}` : '',
                    avoid ? `Avoid: ${avoid}` : '',
                ].filter(Boolean).join(' | ');
            })
            .join(' || ');

        return [
            `${entry.issueId}: ${entry.canonicalFixSummary}`,
            variantPreview ? `Frameworks: ${variantPreview}` : '',
            cheatSheetPreview ? `Cheat sheet guidance: ${cheatSheetPreview}` : '',
            validationPreview ? `Validate: ${validationPreview}` : '',
            unsafePreview ? `Avoid: ${unsafePreview}` : '',
        ].filter(Boolean).join('\n');
    }).join('\n\n');
}
