import * as vscode from 'vscode';
import { PROFILE } from '../profile';
import type { ScanResult } from '../scanner/scanEngine';
import { getRulePackModeLabel } from '../packs/packRuntime';

function getAiConfidenceLabel(finding: ScanResult['findings'][number] | undefined): string | undefined {
    if (!finding || finding.provenance !== 'ai') {
        return undefined;
    }

    return `${Math.round((finding.resolverConfidence ?? finding.confidence ?? 0) * 100)}%`;
}

export class StatusBar {
    private readonly item: vscode.StatusBarItem;

    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.item.command = PROFILE.commands.scanFile;
        this.showIdle();
        this.item.show();
    }

    showIdle(): void {
        this.item.text = `$(shield) ${PROFILE.statusBarLabel}`;
        this.item.tooltip = 'Click to scan current file';
        this.item.backgroundColor = undefined;
    }

    showScanning(): void {
        this.item.text = `$(sync~spin) ${PROFILE.statusBarLabel}: Scanning...`;
        this.item.tooltip = 'Scan in progress';
    }

    showResult(result: Pick<ScanResult, 'score' | 'model' | 'findings' | 'packContext'>): void {
        const icon = result.score >= 8 ? '$(shield-check)' : result.score >= 5 ? '$(shield)' : '$(shield-x)';
        const topRiskFinding = result.findings
            .slice()
            .sort((left, right) => ((right.riskScore ?? 0) - (left.riskScore ?? 0)))[0];
        const packLabel = getRulePackModeLabel(result.packContext);
        this.item.text = `${icon} ${result.score.toFixed(1)}/10 | ${result.model} | ${packLabel}`;
        this.item.tooltip = [
            `Score: ${result.score.toFixed(1)}/10`,
            `Findings: ${result.findings.length}`,
            `Model: ${result.model}`,
            `Intelligence: ${packLabel}`,
            topRiskFinding
                ? `Top risk: ${topRiskFinding.title} | ${topRiskFinding.severity}/${String(topRiskFinding.likelihood ?? 'MEDIUM').toUpperCase()} | ${topRiskFinding.riskScore ?? 'n/a'}/10${getAiConfidenceLabel(topRiskFinding) ? ` | AI ${getAiConfidenceLabel(topRiskFinding)}` : ''}`
                : '',
        ].filter(Boolean).join(' | ');

        if (result.score < 5) {
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (result.score < 8) {
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
            this.item.backgroundColor = undefined;
        }
    }

    showError(message: string): void {
        this.item.text = `$(shield-x) ${PROFILE.statusBarLabel}: Error`;
        this.item.tooltip = message;
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }

    showUnlicensed(): void {
        this.item.text = `$(shield-x) ${PROFILE.statusBarLabel}: No Licence`;
        this.item.command = PROFILE.commands.enterLicence;
        this.item.tooltip = 'Click to enter your licence key';
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }

    dispose(): void {
        this.item.dispose();
    }
}
