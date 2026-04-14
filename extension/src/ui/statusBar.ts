import * as vscode from 'vscode';
import { PROFILE } from '../profile';
import { getRulePackModeLabel, type RulePackRuntimeContext } from '../packs/packRuntime';

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

    showResult(score: number, model: string, findingCount: number, packContext?: RulePackRuntimeContext): void {
        const icon = score >= 8 ? '$(shield-check)' : score >= 5 ? '$(shield)' : '$(shield-x)';
        const packLabel = getRulePackModeLabel(packContext);
        this.item.text = `${icon} ${score.toFixed(1)}/10 | ${model} | ${packLabel}`;
        this.item.tooltip = `Score: ${score.toFixed(1)}/10 | ${findingCount} finding(s) | Model: ${model} | Intelligence: ${packLabel}`;

        if (score < 5) {
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (score < 8) {
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
