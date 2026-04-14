import * as vscode from 'vscode';
import { ScanResult, Finding } from '../scanner/scanEngine';
import { PROFILE } from '../profile';
import { getRulePackModeLabel } from '../packs/packRuntime';
import { resolveRemediationForFinding } from '../frameworks/remediationResolver';

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
            // Root nodes: score header + severity groups
            const items: FindingItem[] = [
                new FindingItem(
                    `Score: ${this.lastResult.score.toFixed(1)}/10`,
                    `${this.lastResult.findings.length} finding(s) | ${this.lastResult.model} | ${getRulePackModeLabel(this.lastResult.packContext)}`,
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
                        `${sev} (${findings.length})`,
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
                    `L${f.line} ${f.title}`,
                    remediation.remediation || f.explanation,
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
                ),
            );
        }

        return [];
    }
}

function buildFindingDetails(finding: Finding): Array<{ label: string; tooltip: string }> {
    const remediation = resolveRemediationForFinding(finding);
    const details: Array<{ label: string; tooltip: string }> = [
        {
            label: `Fix: ${remediation.remediation}`,
            tooltip: remediation.remediation,
        },
    ];

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
    ) {
        super(label, collapsible);
        this.tooltip = tooltip;
        this.description = kind === 'finding' ? finding?.ruleCode : undefined;

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
                : finding.explanation;
            // Navigate to line on click
            this.command = {
                command: PROFILE.commands.revealLine,
                title: 'Go to finding',
                arguments: [finding.line],
            };
        }

        if (kind === 'detail') {
            this.iconPath = new vscode.ThemeIcon('note');
            this.description = undefined;
        }
    }
}
