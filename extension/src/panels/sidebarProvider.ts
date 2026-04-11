import * as vscode from 'vscode';
import { ScanResult, Finding } from '../scanner/scanEngine';

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
                    `${this.lastResult.findings.length} finding(s) | ${this.lastResult.model}`,
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

        // Children: individual findings under a severity group
        return (element.findings ?? []).map(f =>
            new FindingItem(
                `L${f.line} ${f.title}`,
                f.explanation,
                vscode.TreeItemCollapsibleState.None,
                'finding',
                f,
            )
        );
    }
}

class FindingItem extends vscode.TreeItem {
    constructor(
        label: string,
        tooltip: string,
        collapsible: vscode.TreeItemCollapsibleState,
        public readonly kind: 'score' | 'severity' | 'finding',
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
                command: 'owlvex.revealLine',
                title: 'Go to finding',
                arguments: [finding.line],
            };
        }
    }
}
