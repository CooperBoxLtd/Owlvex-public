import type { Finding } from '../scanner/scanEngine';
import { getCanonicalIssueById } from './issueResolver';
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

function normalizeFramework(value: string | undefined): string {
    return String(value ?? '').replace(/[^a-z0-9]/gi, '').toUpperCase();
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

export function buildGroundedRemediationPromptContext(): string {
    const entries = getEffectiveRemediationCatalog();
    if (!entries.length) {
        return '';
    }

    return entries.map(entry => {
        const variantPreview = entry.frameworkVariants
            .slice(0, 3)
            .map(variant => `${variant.framework}: ${variant.summary}`)
            .join(' | ');
        const validationPreview = entry.validationSteps.slice(0, 2).join(' ; ');
        const unsafePreview = entry.unsafeAlternatives.slice(0, 2).join(' ; ');
        return [
            `${entry.issueId}: ${entry.canonicalFixSummary}`,
            variantPreview ? `Frameworks: ${variantPreview}` : '',
            validationPreview ? `Validate: ${validationPreview}` : '',
            unsafePreview ? `Avoid: ${unsafePreview}` : '',
        ].filter(Boolean).join('\n');
    }).join('\n\n');
}
