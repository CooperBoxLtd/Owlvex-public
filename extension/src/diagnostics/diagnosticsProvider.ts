import * as vscode from 'vscode';
import { Finding } from '../scanner/scanEngine';

export class DiagnosticsProvider {
    private readonly collection: vscode.DiagnosticCollection;

    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('owlvex');
    }

    applyFindings(document: vscode.TextDocument, findings: Finding[]): void {
        const config = vscode.workspace.getConfiguration('owlvex');
        const threshold = config.get<string>('severityThreshold', 'MEDIUM');
        const order = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
        const minLevel = order[threshold as keyof typeof order] ?? 1;

        const diagnostics: vscode.Diagnostic[] = findings
            .filter(f => order[f.severity] >= minLevel)
            .map(f => {
                const startLine = Math.max(0, f.line - 1);
                const endLine = Math.max(startLine, f.lineEnd - 1);
                const range = new vscode.Range(
                    new vscode.Position(startLine, 0),
                    new vscode.Position(endLine, Number.MAX_SAFE_INTEGER),
                );

                const diag = new vscode.Diagnostic(
                    range,
                    `[${f.ruleCode}] ${f.title}: ${f.explanation}`,
                    this._vscodeSeverity(f.severity),
                );
                diag.source = `Owlvex (${f.framework})`;
                diag.code = f.ruleCode;
                return diag;
            });

        this.collection.set(document.uri, diagnostics);
    }

    clear(uri?: vscode.Uri): void {
        if (uri) {
            this.collection.delete(uri);
        } else {
            this.collection.clear();
        }
    }

    dispose(): void {
        this.collection.dispose();
    }

    private _vscodeSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'CRITICAL':
            case 'HIGH':
                return vscode.DiagnosticSeverity.Error;
            case 'MEDIUM':
                return vscode.DiagnosticSeverity.Warning;
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }
}
