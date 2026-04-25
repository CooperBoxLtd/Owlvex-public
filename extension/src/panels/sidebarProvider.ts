import * as vscode from 'vscode';
import { ScanResult, Finding } from '../scanner/scanEngine';
import { PROFILE } from '../profile';
import { getRulePackModeLabel } from '../packs/packRuntime';
import { resolveRemediationForFinding } from '../frameworks/remediationResolver';
import { formatFrameworkSummary } from '../frameworks/catalog';

function getFindingLikelihood(finding: Finding): string {
    return String(finding.likelihood ?? 'MEDIUM').toUpperCase();
}

function getAiConfidenceLabel(finding: Finding): string | undefined {
    if (finding.provenance !== 'ai') {
        return undefined;
    }

    return `${Math.round((finding.resolverConfidence ?? finding.confidence ?? 0) * 100)}%`;
}

function getEvidencePostureLabel(finding: Finding): string {
    const confidenceTier = getConfidenceTierLabel(finding);
    const corroboration = getCorroborationLabel(finding);

    if (confidenceTier === 'PROVEN' || corroboration === 'PROVEN') {
        return 'Static proof';
    }

    if (corroboration === 'CORROBORATED') {
        return 'AI-reviewed';
    }

    if (corroboration === 'PARTIAL') {
        return 'Partially validated';
    }

    return 'Needs manual review';
}

function getConfidenceTierLabel(finding: Finding): string {
    return finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE');
}

function getScanTierLabel(finding: Finding): string {
    return finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI');
}

function getScanTierDisplayLabel(value: string): string {
    switch (value) {
        case 'STATIC':
            return 'Static proof';
        case 'TARGETED_AI':
            return 'Targeted AI review';
        case 'REPO_AI':
            return 'Repo-context AI review';
        default:
            return value;
    }
}

function getConfidenceDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Proven';
        case 'PLAUSIBLE':
            return 'Plausible';
        default:
            return value;
    }
}

function getCorroborationDisplayLabel(value: string): string {
    switch (value) {
        case 'PROVEN':
            return 'Proven';
        case 'CORROBORATED':
            return 'Cross-checked';
        case 'PARTIAL':
            return 'Needs confirmation';
        case 'UNVERIFIED':
            return 'Not confirmed yet';
        default:
            return value;
    }
}

function getCorroborationLabel(finding: Finding): string {
    return finding.corroboration ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'UNVERIFIED');
}

function hasPartialAiCoverage(result: ScanResult): boolean {
    return (result.warnings ?? []).some(warning =>
        /deterministic-only|AI coverage intentionally paused|AI provider unavailable|\b429\b|rate limit/i.test(warning),
    );
}

function summarizeCorroborationCounts(findings: Finding[]): string {
    const order: Array<'PROVEN' | 'CORROBORATED' | 'PARTIAL' | 'UNVERIFIED'> = ['PROVEN', 'CORROBORATED', 'PARTIAL', 'UNVERIFIED'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = getCorroborationLabel(finding);
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    const parts = order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase()}: ${counts.get(label)}`);

    return parts.length ? parts.join(' | ') : 'none';
}

function summarizeScanTierCounts(findings: Finding[]): string {
    const order: Array<'STATIC' | 'TARGETED_AI' | 'REPO_AI'> = ['STATIC', 'TARGETED_AI', 'REPO_AI'];
    const counts = new Map<string, number>();

    for (const finding of findings) {
        const label = finding.scanTier ?? (finding.provenance === 'deterministic' ? 'STATIC' : 'TARGETED_AI');
        counts.set(label, (counts.get(label) ?? 0) + 1);
    }

    const parts = order
        .filter(label => (counts.get(label) ?? 0) > 0)
        .map(label => `${label.toLowerCase()}: ${counts.get(label)}`);

    return parts.length ? parts.join(' | ') : 'none';
}

function getPrimaryScanTierLabel(findings: Finding[]): string {
    const order: Array<'REPO_AI' | 'TARGETED_AI' | 'STATIC'> = ['REPO_AI', 'TARGETED_AI', 'STATIC'];
    for (const label of order) {
        if (findings.some(finding => getScanTierLabel(finding) === label)) {
            return label;
        }
    }

    return 'none';
}

function riskRank(finding: Finding): number {
    const severityRank = finding.severity === 'CRITICAL'
        ? 4
        : finding.severity === 'HIGH'
        ? 3
        : finding.severity === 'MEDIUM'
        ? 2
        : 1;
    return (finding.riskScore ?? 0) * 10 + severityRank;
}

export class SidebarProvider implements vscode.TreeDataProvider<FindingItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private lastResult: ScanResult | null = null;

    refresh(result: ScanResult): void {
        this.lastResult = result;
        this._onDidChangeTreeData.fire(undefined);
    }

    clear(): void {
        this.lastResult = null;
        this._onDidChangeTreeData.fire(undefined);
    }

    getLastResult(): ScanResult | null {
        return this.lastResult;
    }

    getTreeItem(element: FindingItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingItem): FindingItem[] {
        if (!this.lastResult) return [];

        if (!element) {
            const topRiskFinding = this.lastResult.findings
                .slice()
                .sort((left, right) => riskRank(right) - riskRank(left))[0];
            const items: FindingItem[] = [
                new FindingItem(
                    `File risk: ${this.lastResult.score.toFixed(1)}/10`,
                    [
                        `Scan: ${this.lastResult.findings.length} finding(s) | ${this.lastResult.model} | ${getRulePackModeLabel(this.lastResult.packContext)}`,
                        this.lastResult.frameworks?.length
                            ? `Frameworks in scope: ${formatFrameworkSummary(this.lastResult.frameworks)}`
                            : '',
                        hasPartialAiCoverage(this.lastResult)
                            ? 'Coverage: partial AI coverage or deterministic-only fallback'
                            : 'Coverage: normal',
                        `Analysis mode: ${getScanTierDisplayLabel(getPrimaryScanTierLabel(this.lastResult.findings))}`,
                        `Analysis mix: ${summarizeScanTierCounts(this.lastResult.findings)}`,
                        `Evidence: ${summarizeCorroborationCounts(this.lastResult.findings)}`,
                        `Project context: ${this.lastResult.projectContextSummary && this.lastResult.projectContextSummary !== 'none' ? this.lastResult.projectContextSummary : 'none'}`,
                        topRiskFinding
                            ? `Start with: ${topRiskFinding.title} | ${topRiskFinding.severity}/${getFindingLikelihood(topRiskFinding)} | ${topRiskFinding.riskScore ?? 'n/a'}/10`
                            : '',
                    ].filter(Boolean).join('\n'),
                    vscode.TreeItemCollapsibleState.None,
                    'score',
                ),
            ];

            const bySeverity: Record<string, Finding[]> = {
                CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [],
            };
            for (const f of this.lastResult.findings) {
                bySeverity[f.severity]?.push(f);
            }

            for (const [sev, findings] of Object.entries(bySeverity)) {
                if (findings.length > 0) {
                    items.push(new FindingItem(
                        `Impact ${sev} (${findings.length})`,
                        '',
                        vscode.TreeItemCollapsibleState.Expanded,
                        'severity',
                        undefined,
                        findings,
                    ));
                }
            }
            return items;
        }

        if (element.kind === 'severity') {
            return (element.findings ?? []).map(f => {
                const remediation = resolveRemediationForFinding(f);
                const hasDetails = Boolean(
                    remediation.frameworkVariant
                    || remediation.recommendedActions.length
                    || remediation.cheatSheetGuidance.length
                    || remediation.validationSteps.length
                    || remediation.unsafeAlternatives.length
                    || remediation.refs.length
                    || remediation.modelNote,
                );

                return new FindingItem(
                    `L${f.line} ${f.title} (${f.riskScore ?? 'n/a'}/10)`,
                    [
                        `Impact: ${f.severity}`,
                        `Likelihood: ${getFindingLikelihood(f)}`,
                        `Contextual risk: ${f.riskScore ?? 'n/a'}/10`,
                        `Analysis mode: ${getScanTierDisplayLabel(getScanTierLabel(f))}`,
                        `Evidence: ${getCorroborationDisplayLabel(getCorroborationLabel(f))}`,
                        remediation.remediation || f.explanation,
                    ].join('\n'),
                    hasDetails ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
                    'finding',
                    f,
                );
            });
        }

        if (element.kind === 'finding' && element.finding) {
            return buildFindingDetails(element.finding).map(detail =>
                new FindingItem(
                    detail.label,
                    detail.tooltip,
                    vscode.TreeItemCollapsibleState.None,
                    'detail',
                    undefined,
                    undefined,
                    detail.command,
                    detail.iconId,
                ),
            );
        }

        return [];
    }
}

function buildFindingDetails(finding: Finding): Array<{ label: string; tooltip: string; command?: vscode.Command; iconId?: string }> {
    const remediation = resolveRemediationForFinding(finding);
    const details: Array<{ label: string; tooltip: string; command?: vscode.Command; iconId?: string }> = [
        {
            label: 'Discuss this finding',
            tooltip: 'Open Owlvex Assistant with this finding preloaded for explanation and remediation discussion.',
            command: {
                command: PROFILE.commands.discussFinding,
                title: 'Discuss this finding',
                arguments: [finding],
            },
            iconId: 'comment-discussion',
        },
        {
            label: 'Fix code',
            tooltip: 'Ask Owlvex to generate a review-only code diff for this finding.',
            command: {
                command: PROFILE.commands.generateFixPreview,
                title: 'Fix code',
                arguments: [finding],
            },
            iconId: 'diff',
        },
        {
            label: `Risk: ${finding.severity}/${getFindingLikelihood(finding)} -> ${finding.riskScore ?? 'n/a'}/10`,
            tooltip: `Impact ${finding.severity}, likelihood ${getFindingLikelihood(finding)}, contextual risk ${finding.riskScore ?? 'n/a'}/10`,
        },
        {
            label: `Analysis mode: ${getScanTierDisplayLabel(getScanTierLabel(finding))}`,
            tooltip: `How Owlvex analyzed this finding: ${getScanTierDisplayLabel(getScanTierLabel(finding))}`,
        },
        {
            label: `Confidence: ${getConfidenceDisplayLabel(getConfidenceTierLabel(finding))}`,
            tooltip: `Owlvex confidence for this finding: ${getConfidenceDisplayLabel(getConfidenceTierLabel(finding))}`,
        },
        {
            label: `Evidence: ${getCorroborationDisplayLabel(getCorroborationLabel(finding))}`,
            tooltip: `Owlvex evidence posture for this finding: ${getCorroborationDisplayLabel(getCorroborationLabel(finding))}`,
        },
        {
            label: `Recommended fix: ${remediation.remediation}`,
            tooltip: remediation.remediation,
        },
    ];

    const aiConfidence = getAiConfidenceLabel(finding);
    if (aiConfidence) {
        details.push({
            label: `AI signal audit trace: ${aiConfidence}`,
            tooltip: `Raw AI-reported score retained for audit trace only. Use the confidence and evidence labels above for decision-making.`,
        });
    }

    if ((finding.likelihoodReasons ?? []).length) {
        details.push({
            label: `Why likely: ${(finding.likelihoodReasons ?? []).join(' | ')}`,
            tooltip: (finding.likelihoodReasons ?? []).join('\n'),
        });
    }

    if (remediation.frameworkVariant) {
        details.push({
            label: `Framework: ${remediation.frameworkVariant.framework} - ${remediation.frameworkVariant.summary}`,
            tooltip: [
                remediation.frameworkVariant.summary,
                remediation.frameworkVariant.recommendedActions.length
                    ? `Actions: ${remediation.frameworkVariant.recommendedActions.join(' | ')}`
                    : '',
            ].filter(Boolean).join('\n'),
        });
    }

    if (remediation.recommendedActions.length) {
        details.push({
            label: `Suggested steps: ${remediation.recommendedActions.join(' | ')}`,
            tooltip: remediation.recommendedActions.join('\n'),
        });
    }

    if (remediation.validationSteps.length) {
        details.push({
            label: `Check: ${remediation.validationSteps.join(' | ')}`,
            tooltip: remediation.validationSteps.join('\n'),
        });
    }

    if (remediation.unsafeAlternatives.length) {
        details.push({
            label: `Avoid this: ${remediation.unsafeAlternatives.join(' | ')}`,
            tooltip: remediation.unsafeAlternatives.join('\n'),
        });
    }

    if (remediation.refs.length) {
        details.push({
            label: `References: ${remediation.refs.join(', ')}`,
            tooltip: remediation.refs.join('\n'),
        });
    }

    if (remediation.cheatSheetGuidance.length) {
        details.push({
            label: `Canonical grounding: ${remediation.cheatSheetGuidance.join(' || ')}`,
            tooltip: remediation.cheatSheetGuidance.join('\n'),
        });
    }

    if (remediation.modelNote) {
        details.push({
            label: `Model note: ${remediation.modelNote}`,
            tooltip: remediation.modelNote,
        });
    }

    return details;
}

class FindingItem extends vscode.TreeItem {
    constructor(
        label: string,
        tooltip: string,
        collapsible: vscode.TreeItemCollapsibleState,
        public readonly kind: 'score' | 'severity' | 'finding' | 'detail',
        public readonly finding?: Finding,
        public readonly findings?: Finding[],
        command?: vscode.Command,
        iconId?: string,
    ) {
        super(label, collapsible);
        this.tooltip = tooltip;
        this.description = kind === 'finding' ? finding?.ruleCode : undefined;
        this.command = command;

        if (kind === 'finding' && finding) {
            const isDeterministic = finding.provenance === 'deterministic';
            this.iconPath = new vscode.ThemeIcon(
                isDeterministic
                    ? 'shield'
                    : finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                    ? 'error'
                    : finding.severity === 'MEDIUM'
                    ? 'warning'
                    : 'info',
            );
            // Description: provenance badge + rule code
            this.description = isDeterministic
                ? `⚡ ${finding.ruleCode}`
                : finding.ruleCode;
            // Tooltip: include provenance context
            this.tooltip = isDeterministic
                ? `[Static proof] ${finding.explanation}`
                : `[${getEvidencePostureLabel(finding)}] ${finding.explanation}${getAiConfidenceLabel(finding) ? ` AI signal ${getAiConfidenceLabel(finding)} retained as audit trace.` : ''}`;
            // Navigate to line on click
            this.command = {
                command: PROFILE.commands.revealLine,
                title: 'Go to finding',
                arguments: [finding.line],
            };
        }

        if (kind === 'detail') {
            this.iconPath = new vscode.ThemeIcon(iconId ?? 'note');
            this.description = undefined;
        }
    }
}
