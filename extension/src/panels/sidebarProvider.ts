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

function getConfidenceTierLabel(finding: Finding): string {
    return finding.confidenceTier ?? (finding.provenance === 'deterministic' ? 'PROVEN' : 'PLAUSIBLE');
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
                    `Score: ${this.lastResult.score.toFixed(1)}/10`,
                    [
                        `${this.lastResult.findings.length} finding(s) | ${this.lastResult.model} | ${getRulePackModeLabel(this.lastResult.packContext)}`,
                        this.lastResult.frameworks?.length
                            ? `Frameworks in scope: ${formatFrameworkSummary(this.lastResult.frameworks)}`
                            : '',
                        hasPartialAiCoverage(this.lastResult)
                            ? 'Coverage posture: partial AI coverage or deterministic-only fallback'
                            : 'Coverage posture: normal',
                        `Corroboration posture: ${summarizeCorroborationCounts(this.lastResult.findings)}`,
                        topRiskFinding
                            ? `Top risk: ${topRiskFinding.title} | ${topRiskFinding.severity}/${getFindingLikelihood(topRiskFinding)} | ${topRiskFinding.riskScore ?? 'n/a'}/10`
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
                        `Corroboration: ${getCorroborationLabel(f)}`,
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
            label: 'Review fix',
            tooltip: 'Ask Owlvex to open a review-only code diff for this finding.',
            command: {
                command: PROFILE.commands.generateFixPreview,
                title: 'Review fix',
                arguments: [finding],
            },
            iconId: 'diff',
        },
        {
            label: `Risk: ${finding.severity}/${getFindingLikelihood(finding)} -> ${finding.riskScore ?? 'n/a'}/10`,
            tooltip: `Impact ${finding.severity}, likelihood ${getFindingLikelihood(finding)}, contextual risk ${finding.riskScore ?? 'n/a'}/10`,
        },
        {
            label: `Confidence tier: ${getConfidenceTierLabel(finding)}`,
            tooltip: `Owlvex confidence tier for this finding: ${getConfidenceTierLabel(finding)}`,
        },
        {
            label: `Corroboration: ${getCorroborationLabel(finding)}`,
            tooltip: `Owlvex corroboration posture for this finding: ${getCorroborationLabel(finding)}`,
        },
        {
            label: `Fix: ${remediation.remediation}`,
            tooltip: remediation.remediation,
        },
    ];

    const aiConfidence = getAiConfidenceLabel(finding);
    if (aiConfidence) {
        details.push({
            label: `AI confidence: ${aiConfidence}`,
            tooltip: `AI-reported confidence for this finding: ${aiConfidence}`,
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

    if (remediation.validationSteps.length) {
        details.push({
            label: `Validate: ${remediation.validationSteps.join(' | ')}`,
            tooltip: remediation.validationSteps.join('\n'),
        });
    }

    if (remediation.unsafeAlternatives.length) {
        details.push({
            label: `Avoid: ${remediation.unsafeAlternatives.join(' | ')}`,
            tooltip: remediation.unsafeAlternatives.join('\n'),
        });
    }

    if (remediation.refs.length) {
        details.push({
            label: `Sources: ${remediation.refs.join(', ')}`,
            tooltip: remediation.refs.join('\n'),
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
                ? `[Deterministic] ${finding.explanation}`
                : `[AI ${getAiConfidenceLabel(finding) ?? 'n/a'}] ${finding.explanation}`;
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
