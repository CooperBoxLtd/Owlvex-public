import * as vscode from 'vscode';
import * as path from 'path';
import { LicenceManager } from './licence/licenceManager';
import { ProviderRegistry } from './providers/registry';
import { ScanEngine, ScanResult } from './scanner/scanEngine';
import { DiagnosticsProvider } from './diagnostics/diagnosticsProvider';
import { StatusBar } from './ui/statusBar';
import { SidebarProvider } from './panels/sidebarProvider';
import { ChatViewProvider } from './panels/chatViewProvider';
import { pickScanFile, pickScanRoot, scanFolder } from './scanner/workspaceScanner';
import { generateReportFromSnapshot, ReportSnapshot } from './scanner/reportGenerator';
import { FRAMEWORK_CATALOG, formatFrameworkSummary } from './frameworks/catalog';

export let secrets: vscode.SecretStorage;

const MAX_STORED_SCANS = 20;
const scanStore = new Map<string, ScanResult>();
const SCAN_STORE_KEY = 'owlvex.scanStore';
const LAST_REPORT_SNAPSHOT_KEY = 'owlvex.lastReportSnapshot';

interface ScanFileCommandResult {
    status: 'completed' | 'cancelled';
    uri?: vscode.Uri;
    result?: ScanResult;
}

interface ScanWorkspaceCommandResult {
    status: 'completed' | 'cancelled' | 'empty';
    root?: vscode.Uri;
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ReportCommandResult {
    status: 'completed' | 'cancelled' | 'empty';
    reportUri?: vscode.Uri;
    averageScore?: number;
    providers?: string;
    models?: string;
    summary?: {
        completed: number;
        totalFindings: number;
        errors: string[];
        results: Array<{ uri: vscode.Uri; result: ScanResult }>;
    };
}

function storeScanResult(scanId: string, result: ScanResult): void {
    if (scanStore.size >= MAX_STORED_SCANS) {
        const firstKey = scanStore.keys().next().value;
        if (firstKey) scanStore.delete(firstKey);
    }
    scanStore.set(scanId, normalizeScanResult(result));
}

function serializeScanStore(): Array<{ scanId: string; result: ScanResult }> {
    return Array.from(scanStore.entries()).map(([scanId, result]) => ({ scanId, result }));
}

function normalizeScanResult(result: ScanResult): ScanResult {
    return {
        ...result,
        warnings: result.warnings ?? [],
    };
}

function getFrameworkConfigurationTarget(): vscode.ConfigurationTarget {
    return vscode.workspace.workspaceFolders?.length
        ? vscode.ConfigurationTarget.Workspace
        : vscode.ConfigurationTarget.Global;
}

async function readErrorResponse(res: Response, prefix: string): Promise<string> {
    const text = await res.text();
    if (!text.trim()) {
        return `${prefix}: HTTP ${res.status}`;
    }

    try {
        const parsed = JSON.parse(text);
        return parsed?.detail ? `${prefix}: ${parsed.detail}` : `${prefix}: HTTP ${res.status}`;
    } catch {
        return `${prefix}: ${text.trim().slice(0, 180)}`;
    }
}

async function readJsonResponse(res: Response, prefix: string): Promise<any> {
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch {
        throw new Error(text.trim() ? `${prefix}: ${text.trim().slice(0, 180)}` : prefix);
    }
}

export function activate(context: vscode.ExtensionContext) {
    secrets = context.secrets;

    const config = vscode.workspace.getConfiguration('owlvex');
    const apiUrl = config.get<string>('apiUrl', 'http://owlvex.local');

    const licenceMgr = new LicenceManager(context.secrets);
    const registry = new ProviderRegistry();
    const scanEngine = new ScanEngine(licenceMgr, registry);
    const diagnostics = new DiagnosticsProvider();
    const statusBar = new StatusBar();
    const sidebar = new SidebarProvider();
    const restoredScans = context.workspaceState.get<Array<{ scanId: string; result: ScanResult }>>(SCAN_STORE_KEY, []);
    for (const item of restoredScans) {
        scanStore.set(item.scanId, normalizeScanResult(item.result));
    }
    const lastStoredScan = restoredScans[restoredScans.length - 1]?.result;
    if (lastStoredScan) {
        sidebar.refresh(lastStoredScan);
    }

    const persistScans = async () => {
        await context.workspaceState.update(SCAN_STORE_KEY, serializeScanStore());
    };

    const persistLastReportSnapshot = async (snapshot: ReportSnapshot) => {
        await context.workspaceState.update(LAST_REPORT_SNAPSHOT_KEY, {
            ...snapshot,
            outputRoot: snapshot.outputRoot.toString(),
            results: snapshot.results.map(item => ({
                uri: item.uri.toString(),
                result: item.result,
            })),
        });
    };

    const restoreLastReportSnapshot = (): ReportSnapshot | undefined => {
        const raw = context.workspaceState.get<any>(LAST_REPORT_SNAPSHOT_KEY);
        if (!raw?.results?.length || !raw?.outputRoot) return undefined;
        return {
            targetLabel: raw.targetLabel,
            outputRoot: vscode.Uri.parse(raw.outputRoot),
            errors: raw.errors ?? [],
            results: raw.results.map((item: any) => ({
                uri: vscode.Uri.parse(item.uri),
                result: item.result as ScanResult,
            })),
        };
    };

    const createAndOpenReport = async (snapshot: ReportSnapshot) => {
        const safeSnapshot = normalizeReportSnapshot(snapshot);
        const reportUri = await generateReportFromSnapshot(safeSnapshot.outputRoot, safeSnapshot);
        const reportDoc = await vscode.workspace.openTextDocument(reportUri);
        await vscode.window.showTextDocument(reportDoc, { preview: false });

        const providerNames = [...new Set(safeSnapshot.results.map(item => item.result.provider))].join(', ') || 'unknown';
        const modelNames = [...new Set(safeSnapshot.results.map(item => item.result.model))].join(', ') || 'unknown';
        const averageScore = safeSnapshot.results.length
            ? safeSnapshot.results.reduce((total, item) => total + item.result.score, 0) / safeSnapshot.results.length
            : 0;
        const totalFindings = safeSnapshot.results.reduce((total, item) => total + item.result.findings.length, 0);
        const warningCount = safeSnapshot.results.reduce((total, item) => total + (item.result.warnings ?? []).length, 0);

        statusBar.showResult(averageScore, modelNames, totalFindings);
        vscode.window.showInformationMessage(
            `Owlvex: Report created for ${safeSnapshot.results.length} file(s) with ${totalFindings} finding(s) using ${providerNames}/${modelNames}.${warningCount ? ` ${warningCount} warning(s) were captured.` : ''}`
        );

        return {
            reportUri,
            averageScore,
            providers: providerNames,
            models: modelNames,
            summary: {
                completed: safeSnapshot.results.length,
                totalFindings,
                errors: safeSnapshot.errors,
                results: safeSnapshot.results,
            },
        };
    };

    const normalizeReportSnapshot = (snapshot: ReportSnapshot): ReportSnapshot => {
        if (snapshot.outputRoot?.scheme === 'file') {
            return snapshot;
        }

        const fallbackRoot = snapshot.results[0]?.uri
            ? vscode.Uri.file(path.dirname(snapshot.results[0].uri.fsPath))
            : vscode.workspace.workspaceFolders?.[0]?.uri;

        if (!fallbackRoot) {
            return snapshot;
        }

        return {
            ...snapshot,
            outputRoot: fallbackRoot,
            errors: [
                ...snapshot.errors,
                'Report output root was invalid, so Owlvex used the first scanned file folder instead.',
            ],
        };
    };

    const chatView = new ChatViewProvider(registry, context.workspaceState);

    vscode.window.registerTreeDataProvider('owlvex.findings', sidebar);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(ChatViewProvider.viewType, chatView)
    );

    licenceMgr.validate(apiUrl).then(() => {
        statusBar.showIdle();
    }).catch(() => {
        statusBar.showUnlicensed();
    });

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.enterLicence', async () => {
            const key = await vscode.window.showInputBox({
                prompt: 'Enter your Owlvex licence key',
                placeHolder: 'owlvex_lic_...',
                ignoreFocusOut: true,
                password: true,
            });
            if (!key) return;

            await licenceMgr.storeKey(key);
            try {
                const info = await licenceMgr.validate(apiUrl);
                vscode.window.showInformationMessage(
                    `Owlvex activated - ${info.plan} plan (${info.teamName})`
                );
                statusBar.showIdle();
            } catch (error: any) {
                vscode.window.showErrorMessage(`Licence validation failed: ${error.message}`);
                statusBar.showUnlicensed();
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.selectFrameworks', async () => {
            const currentSelection = config.get<string[]>('frameworks', ['OWASP', 'STRIDE']);
            let allowedFrameworks = licenceMgr.getCachedInfo()?.features.frameworks;
            if (!allowedFrameworks?.length) {
                try {
                    const info = await licenceMgr.validate(apiUrl);
                    allowedFrameworks = info.features.frameworks;
                } catch {
                    allowedFrameworks = FRAMEWORK_CATALOG.map(item => item.code);
                }
            }

            const availableFrameworks = FRAMEWORK_CATALOG.filter(item => allowedFrameworks?.includes(item.code));
            if (!availableFrameworks.length) {
                vscode.window.showWarningMessage('Owlvex: No frameworks are available for this licence.');
                return;
            }

            const picked = await vscode.window.showQuickPick(
                availableFrameworks.map(item => ({
                    label: item.code,
                    description: `${item.name} ${item.version}`,
                    detail: item.description,
                    picked: currentSelection.includes(item.code),
                })),
                {
                    canPickMany: true,
                    placeHolder: 'Select one or more frameworks for Owlvex scans and reports',
                    title: 'Owlvex Framework Selection',
                },
            );

            if (!picked) return;
            if (!picked.length) {
                vscode.window.showWarningMessage('Owlvex: Select at least one framework.');
                return;
            }

            const selectedCodes = picked.map(item => item.label);
            await vscode.workspace
                .getConfiguration('owlvex')
                .update('frameworks', selectedCodes, getFrameworkConfigurationTarget());

            vscode.window.showInformationMessage(
                `Owlvex: Frameworks set to ${formatFrameworkSummary(selectedCodes)}`
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.scanFile', async (requestedUri?: vscode.Uri): Promise<ScanFileCommandResult> => {
            const fileUri = requestedUri ?? await pickScanFile();
            if (!fileUri) {
                return { status: 'cancelled' };
            }

            const document = await vscode.workspace.openTextDocument(fileUri);
            const editor = await vscode.window.showTextDocument(document, { preview: false });

            statusBar.showScanning();
            diagnostics.clear(editor.document.uri);
            sidebar.clear();

            try {
                const result = await scanEngine.scanDocument(editor.document);
                storeScanResult(result.scanId, result);
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(editor.document.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(editor.document.uri.fsPath)),
                    errors: [],
                    results: [{ uri: editor.document.uri, result }],
                });
                diagnostics.applyFindings(editor.document, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result.score, result.model, result.findings.length);
                chatView.setLastScanTarget(`File: ${vscode.workspace.asRelativePath(editor.document.uri, false)}`);

                vscode.window.showInformationMessage(
                    `Owlvex: Score ${result.score.toFixed(1)}/10 - ${result.findings.length} finding(s)${(result.warnings ?? []).length ? ` (${(result.warnings ?? []).length} warning(s))` : ''}`
                );

                return { status: 'completed', uri: editor.document.uri, result };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`Owlvex scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc: vscode.TextDocument) => {
            const cfg = vscode.workspace.getConfiguration('owlvex');
            if (!cfg.get<boolean>('scanOnSave', false)) return;

            statusBar.showScanning();
            try {
                const result = await scanEngine.scanDocument(doc);
                storeScanResult(result.scanId, result);
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(doc.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(doc.uri.fsPath)),
                    errors: [],
                    results: [{ uri: doc.uri, result }],
                });
                diagnostics.applyFindings(doc, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result.score, result.model, result.findings.length);
                chatView.setLastScanTarget(`Saved file: ${vscode.workspace.asRelativePath(doc.uri, false)}`);
            } catch (error: any) {
                statusBar.showError(error.message);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.switchModel', async () => {
            const provider = registry.getActive();
            const models = await provider.listModels();
            const picked = await vscode.window.showQuickPick(models, {
                placeHolder: `Select model (current: ${provider.selectedModel})`,
            });

            if (picked) {
                provider.selectedModel = picked;
                vscode.window.showInformationMessage(`Owlvex: Model switched to ${picked}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.setupAI', async () => {
            const provider = registry.getActive();
            if (provider.id === 'ollama') {
                vscode.window.showInformationMessage('Ollama uses no API key - ensure it is reachable from the configured host.');
                return;
            }

            const key = await vscode.window.showInputBox({
                prompt: `Enter API key for ${provider.name}`,
                ignoreFocusOut: true,
                password: true,
            });
            if (!key) return;

            await context.secrets.store(`owlvex.${provider.id}.apiKey`, key);
            const { success, latencyMs } = await provider.testConnection();
            if (success) {
                vscode.window.showInformationMessage(`${provider.name} connected (${latencyMs}ms)`);
            } else {
                vscode.window.showErrorMessage(`${provider.name} connection failed - check your key`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.scanWorkspace', async (requestedRoot?: vscode.Uri): Promise<ScanWorkspaceCommandResult> => {
            const root = requestedRoot ?? await pickScanRoot();
            if (!root) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            const summary = await scanFolder({
                root,
                scanEngine,
                diagnostics,
            });

            for (const item of summary.results) {
                storeScanResult(item.result.scanId, item.result);
            }
            await persistScans();
            await persistLastReportSnapshot({
                targetLabel: vscode.workspace.asRelativePath(root, false) || root.fsPath,
                outputRoot: root,
                errors: summary.errors,
                results: summary.results,
            });
            chatView.setLastScanTarget(`Folder: ${vscode.workspace.asRelativePath(root, false) || root.fsPath}`);

            const msg = `Owlvex: Scanned ${summary.completed} file(s) in ${root.fsPath} - ${summary.totalFindings} finding(s)`;
            if (summary.errors.length) {
                vscode.window.showWarningMessage(`${msg} (${summary.errors.length} error(s) - see output)`);
            } else if (summary.completed > 0) {
                vscode.window.showInformationMessage(msg);
            }

            return { root, ...summary };
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.scanWorkspaceReport', async (): Promise<ReportCommandResult> => {
            try {
                const lastSnapshot = restoreLastReportSnapshot();
                const options: vscode.QuickPickItem[] = [];
                if (lastSnapshot) {
                    options.push({
                        label: 'Use last scan',
                        description: lastSnapshot.targetLabel,
                    });
                }
                options.push(
                    { label: 'Scan selected file and create report', description: 'Pick a file, scan it, then create a report' },
                    { label: 'Scan selected folder and create report', description: 'Pick a folder, scan it, then create a report' },
                );

                const picked = await vscode.window.showQuickPick(options, {
                    placeHolder: 'Choose how to create the report',
                });
                if (!picked) return { status: 'cancelled' };

                if (picked.label === 'Use last scan' && lastSnapshot) {
                    chatView.setLastScanTarget(`Report from last scan: ${lastSnapshot.targetLabel}`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(lastSnapshot)),
                    };
                }

                if (picked.label === 'Scan selected file and create report') {
                    const fileUri = await pickScanFile();
                    if (!fileUri) return { status: 'cancelled' };

                    const document = await vscode.workspace.openTextDocument(fileUri);
                    await vscode.window.showTextDocument(document, { preview: false });

                    statusBar.showScanning();
                    diagnostics.clear(document.uri);
                    sidebar.clear();

                    const result = await scanEngine.scanDocument(document);
                    storeScanResult(result.scanId, result);
                    await persistScans();
                    diagnostics.applyFindings(document, result.findings);
                    sidebar.refresh(result);
                    statusBar.showResult(result.score, result.model, result.findings.length);

                    const snapshot: ReportSnapshot = {
                        targetLabel: vscode.workspace.asRelativePath(document.uri, false),
                        outputRoot: vscode.Uri.file(path.dirname(document.uri.fsPath)),
                        errors: [],
                        results: [{ uri: document.uri, result }],
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report file: ${snapshot.targetLabel}`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(snapshot)),
                    };
                }

                const root = await pickScanRoot();
                if (!root) return { status: 'cancelled' };

                statusBar.showScanning();
                const summary = await scanFolder({
                    root,
                    scanEngine,
                    diagnostics,
                });

                for (const item of summary.results) {
                    storeScanResult(item.result.scanId, item.result);
                }
                await persistScans();

                if (!summary.completed) {
                    statusBar.showIdle();
                    return {
                        status: summary.status,
                        summary: {
                            completed: summary.completed,
                            totalFindings: summary.totalFindings,
                            errors: summary.errors,
                            results: summary.results,
                        },
                    };
                }

                const snapshot: ReportSnapshot = {
                    targetLabel: vscode.workspace.asRelativePath(root, false) || root.fsPath,
                    outputRoot: root,
                    errors: summary.errors,
                    results: summary.results,
                };
                await persistLastReportSnapshot(snapshot);
                chatView.setLastScanTarget(`Report folder: ${snapshot.targetLabel}`);
                return {
                    status: 'completed',
                    ...(await createAndOpenReport(snapshot)),
                };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`Owlvex report failed: ${error.message}`);
                return { status: 'cancelled' };
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.openPromptEditor', async () => {
            await chatView.show();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.compareScans', async () => {
            const cfg = vscode.workspace.getConfiguration('owlvex');
            const compareApiUrl = cfg.get<string>('apiUrl', 'http://owlvex.local');
            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                vscode.window.showErrorMessage('No licence key. Run "Owlvex: Enter Licence Key".');
                return;
            }

            const storedIds = Array.from(scanStore.keys());
            if (storedIds.length < 2) {
                vscode.window.showWarningMessage(
                    'Owlvex: Need at least 2 scans in this session to compare. Scan a file or folder twice first.'
                );
                return;
            }

            const scanAId = await vscode.window.showQuickPick(storedIds, {
                placeHolder: 'Select baseline scan (Scan A)',
            });
            if (!scanAId) return;

            const scanBId = await vscode.window.showQuickPick(
                storedIds.filter(id => id !== scanAId),
                { placeHolder: 'Select comparison scan (Scan B)' },
            );
            if (!scanBId) return;

            const scanA = scanStore.get(scanAId)!;
            const scanB = scanStore.get(scanBId)!;

            try {
                const res = await fetch(`${compareApiUrl}/v1/scans/compare`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Licence-Key': licenceKey,
                    },
                    body: JSON.stringify({
                        scan_a_id: scanAId,
                        scan_b_id: scanBId,
                        findings_a: scanA.findings.map(f => ({
                            issue_id: f.canonicalId,
                            canonical_title: f.canonicalTitle,
                            line: f.line,
                            framework: f.framework,
                            rule_code: f.ruleCode,
                            severity: f.severity,
                            title: f.title,
                        })),
                        findings_b: scanB.findings.map(f => ({
                            issue_id: f.canonicalId,
                            canonical_title: f.canonicalTitle,
                            line: f.line,
                            framework: f.framework,
                            rule_code: f.ruleCode,
                            severity: f.severity,
                            title: f.title,
                        })),
                        score_a: scanA.score,
                        score_b: scanB.score,
                    }),
                });

                if (!res.ok) {
                    throw new Error(await readErrorResponse(res, 'Compare request failed'));
                }

                const diff = await readJsonResponse(res, 'Compare response returned invalid JSON');
                const scoreChange = diff.score_change > 0
                    ? `+${diff.score_change.toFixed(1)}`
                    : diff.score_change.toFixed(1);

                const panel = vscode.window.createWebviewPanel(
                    'owlvexComparison',
                    'Owlvex: Scan Comparison',
                    vscode.ViewColumn.One,
                    {},
                );

                panel.webview.html = buildComparisonHtmlV2(diff, scoreChange);
            } catch (error: any) {
                vscode.window.showErrorMessage(`Owlvex compare failed: ${error.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('owlvex.revealLine', (line: number) => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) return;
            const pos = new vscode.Position(Math.max(0, line - 1), 0);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        })
    );

    context.subscriptions.push(diagnostics, statusBar);
}

function buildComparisonHtml(diff: any, scoreChange: string): string {
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = diff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (diff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (diff.resolved_finding_details ?? []).map((f: any) =>
        `<tr class="resolved"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const canonicalRows = canonicalChanges.map((item: any) => {
        const delta = Number(item.delta ?? 0);
        const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
        const deltaClass = delta > 0 ? 'negative' : delta < 0 ? 'positive' : '';
        const issueLabel = item.title || item.issue_id || 'Unresolved finding';
        const issueId = item.issue_id ? `<div class="subtle">${item.issue_id}</div>` : '<div class="subtle">unresolved</div>';
        const frameworks = (item.frameworks ?? []).join(', ') || 'n/a';
        const reduction = (item.count_a ?? 0) > 0
            ? `${Math.round((((item.count_b ?? 0) - (item.count_a ?? 0)) / (item.count_a ?? 0)) * 100)}%`
            : 'n/a';
        return `<tr>
<td><strong>${issueLabel}</strong>${issueId}</td>
<td>${item.severity ?? 'n/a'}</td>
<td>${item.count_a ?? 0}</td>
<td>${item.count_b ?? 0}</td>
<td class="${deltaClass}">${deltaLabel}</td>
<td class="${deltaClass}">${reduction}</td>
<td>${frameworks}</td>
</tr>`;
    }).join('');

    const topImprovements = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))
        .slice(0, 5)
        .map((item: any) => {
            const before = Number(item.count_a ?? 0);
            const after = Number(item.count_b ?? 0);
            const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
            return `<li><strong>${item.title || item.issue_id}</strong> <span class="positive">↓ ${reduction}%</span> <span class="subtle">(${before} → ${after})</span></li>`;
        })
        .join('');

    const newRisks = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))
        .slice(0, 5)
        .map((item: any) =>
            `<li><strong>${item.title || item.issue_id}</strong> <span class="negative">+${item.delta}</span> <span class="subtle">(${item.count_a ?? 0} → ${item.count_b ?? 0})</span></li>`
        )
        .join('');

    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
  h1 { font-size: 18px; }
  .summary { display: flex; gap: 24px; margin: 16px 0; }
  .stat { background: var(--vscode-editor-inactiveSelectionBackground); padding: 12px 20px; border-radius: 6px; text-align: center; }
  .stat .value { font-size: 28px; font-weight: bold; }
  .stat .label { font-size: 12px; opacity: 0.7; }
  .positive { color: #4ec9b0; }
  .negative { color: #f48771; }
  .subtle { font-size: 12px; opacity: 0.7; margin-top: 2px; }
  .callouts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 24px 0; }
  .card { background: var(--vscode-editor-inactiveSelectionBackground); padding: 16px; border-radius: 8px; }
  .card h2 { margin-top: 0; font-size: 14px; }
  .card ul { margin: 0; padding-left: 18px; }
  .card li { margin: 8px 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { text-align: left; padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 12px; opacity: 0.7; }
  td { padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; vertical-align: top; }
  tr.new td:first-child { color: #f48771; font-weight: bold; }
  tr.resolved td:first-child { color: #4ec9b0; font-weight: bold; }
  h2 { font-size: 14px; margin-top: 24px; }
</style></head><body>
<h1>Scan Comparison</h1>
<div class="summary">
  <div class="stat"><div class="value ${Number(scoreChange) >= 0 ? 'positive' : 'negative'}">${scoreChange}</div><div class="label">Score Change</div></div>
  <div class="stat"><div class="value negative">${diff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${diff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
</div>
${canonicalRows ? `<h2>Canonical Issue Changes</h2><table><thead><tr><th>Owlvex Issue</th><th>Severity</th><th>Before</th><th>After</th><th>Δ</th><th>Frameworks</th></tr></thead><tbody>${canonicalRows}</tbody></table>` : '<p>No canonical issue changes.</p>'}
${newRows ? `<h2>New Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${newRows}</tbody></table>` : '<p>No new findings.</p>'}
${resolvedRows ? `<h2>Resolved Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${resolvedRows}</tbody></table>` : ''}
</body></html>`;
}

function buildComparisonHtmlV2(diff: any, scoreChange: string): string {
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = diff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (diff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (diff.resolved_finding_details ?? []).map((f: any) =>
        `<tr class="resolved"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');

    const canonicalRows = canonicalChanges.map((item: any) => {
        const delta = Number(item.delta ?? 0);
        const deltaLabel = delta > 0 ? `+${delta}` : `${delta}`;
        const deltaClass = delta > 0 ? 'negative' : delta < 0 ? 'positive' : '';
        const issueLabel = item.title || item.issue_id || 'Unresolved finding';
        const issueId = item.issue_id ? `<div class="subtle">${item.issue_id}</div>` : '<div class="subtle">unresolved</div>';
        const frameworks = (item.frameworks ?? []).join(', ') || 'n/a';
        const reduction = (item.count_a ?? 0) > 0
            ? `${Math.round((((item.count_b ?? 0) - (item.count_a ?? 0)) / (item.count_a ?? 0)) * 100)}%`
            : 'n/a';
        return `<tr>
<td><strong>${issueLabel}</strong>${issueId}</td>
<td>${item.severity ?? 'n/a'}</td>
<td>${item.count_a ?? 0}</td>
<td>${item.count_b ?? 0}</td>
<td class="${deltaClass}">${deltaLabel}</td>
<td class="${deltaClass}">${reduction}</td>
<td>${frameworks}</td>
</tr>`;
    }).join('');

    const topImprovements = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))
        .slice(0, 5)
        .map((item: any) => {
            const before = Number(item.count_a ?? 0);
            const after = Number(item.count_b ?? 0);
            const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
            return `<li><strong>${item.title || item.issue_id}</strong> <span class="positive">down ${reduction}%</span> <span class="subtle">(${before} -> ${after})</span></li>`;
        })
        .join('');

    const newRisks = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))
        .slice(0, 5)
        .map((item: any) =>
            `<li><strong>${item.title || item.issue_id}</strong> <span class="negative">+${item.delta}</span> <span class="subtle">(${item.count_a ?? 0} -> ${item.count_b ?? 0})</span></li>`
        )
        .join('');

    const biggestImprovement = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) < 0)
        .sort((a: any, b: any) => Number(a.delta ?? 0) - Number(b.delta ?? 0))[0];
    const biggestRegression = canonicalChanges
        .filter((item: any) => Number(item.delta ?? 0) > 0)
        .sort((a: any, b: any) => Number(b.delta ?? 0) - Number(a.delta ?? 0))[0];

    const narrativeParts: string[] = [];
    if (biggestImprovement) {
        const before = Number(biggestImprovement.count_a ?? 0);
        const after = Number(biggestImprovement.count_b ?? 0);
        const reduction = before > 0 ? Math.round(((before - after) / before) * 100) : 0;
        narrativeParts.push(
            `The largest improvement was in ${biggestImprovement.title || biggestImprovement.issue_id}, reduced from ${before} to ${after} occurrences (${reduction}% reduction).`
        );
    }
    if (biggestRegression) {
        narrativeParts.push(
            `New risk was introduced in ${biggestRegression.title || biggestRegression.issue_id}, increasing from ${biggestRegression.count_a ?? 0} to ${biggestRegression.count_b ?? 0} occurrences.`
        );
    }
    if (!narrativeParts.length) {
        narrativeParts.push('No major canonical issue movement was detected between these two scans.');
    }

    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 24px; max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .lede { opacity: 0.8; margin-bottom: 20px; }
  .hero { background: linear-gradient(135deg, rgba(78,201,176,0.10), rgba(86,156,214,0.08)); border: 1px solid var(--vscode-panel-border); border-radius: 12px; padding: 18px 20px; margin-bottom: 24px; }
  .hero .eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 11px; opacity: 0.7; margin-bottom: 6px; }
  .hero .headline { font-size: 30px; font-weight: 700; line-height: 1.1; margin-bottom: 8px; }
  .hero .headline.positive { color: #4ec9b0; }
  .hero .headline.negative { color: #f48771; }
  .hero .support { font-size: 14px; opacity: 0.85; }
  .summary { display: flex; gap: 24px; margin: 16px 0; flex-wrap: wrap; }
  .stat { background: var(--vscode-editor-inactiveSelectionBackground); padding: 12px 20px; border-radius: 6px; text-align: center; min-width: 140px; }
  .stat .value { font-size: 28px; font-weight: bold; }
  .stat .label { font-size: 12px; opacity: 0.7; }
  .positive { color: #4ec9b0; }
  .negative { color: #f48771; }
  .subtle { font-size: 12px; opacity: 0.7; margin-top: 2px; }
  .callouts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 24px 0; }
  .card { background: var(--vscode-editor-inactiveSelectionBackground); padding: 16px; border-radius: 8px; }
  .card h2 { margin-top: 0; font-size: 14px; }
  .card ul { margin: 0; padding-left: 18px; }
  .card li { margin: 8px 0; }
  .legend { opacity: 0.75; font-size: 12px; margin-top: 8px; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { text-align: left; padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 12px; opacity: 0.7; }
  td { padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; vertical-align: top; }
  tr.new td:first-child { color: #f48771; font-weight: bold; }
  tr.resolved td:first-child { color: #4ec9b0; font-weight: bold; }
  h2 { font-size: 14px; margin-top: 24px; }
</style></head><body>
<h1>Scan Comparison</h1>
<div class="lede">A canonical before/after view of how security changed between the two scans.</div>
<div class="hero">
  <div class="eyebrow">Security Posture</div>
  <div class="headline ${weightedAfter <= weightedBefore ? 'positive' : 'negative'}">${weightedAfter <= weightedBefore ? `Improved by ${weightedImprovement}%` : `Regressed by ${Math.abs(weightedImprovement)}%`}</div>
  <div class="support">Weighted exposure moved from ${weightedBefore} to ${weightedAfter}. ${diff.resolved_findings ?? 0} findings were resolved and ${diff.new_findings ?? 0} new findings were introduced.</div>
</div>
<div class="summary">
  <div class="stat"><div class="value ${Number(scoreChange) >= 0 ? 'positive' : 'negative'}">${scoreChange}</div><div class="label">Score Change</div></div>
  <div class="stat"><div class="value negative">${diff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${diff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
  <div class="stat"><div class="value ${weightedAfter <= weightedBefore ? 'positive' : 'negative'}">${weightedImprovement}%</div><div class="label">Weighted Improvement</div></div>
</div>
<div class="summary">
  <div class="stat"><div class="value">${weightedBefore}</div><div class="label">Weighted Exposure Before</div></div>
  <div class="stat"><div class="value">${weightedAfter}</div><div class="label">Weighted Exposure After</div></div>
</div>
<div class="legend">Weighted exposure uses severity weights: Critical=4, High=3, Medium=2, Low=1.</div>
<div class="callouts">
  <div class="card">
    <h2>Top Improvements</h2>
    ${topImprovements ? `<ul>${topImprovements}</ul>` : '<p>No major reductions.</p>'}
  </div>
  <div class="card">
    <h2>New Risk Introduced</h2>
    ${newRisks ? `<ul>${newRisks}</ul>` : '<p>No new canonical risks introduced.</p>'}
  </div>
</div>
<h2>What Changed</h2>
<p>${narrativeParts.join(' ')}</p>
${canonicalRows ? `<h2>Canonical Issue Changes</h2><table><thead><tr><th>Owlvex Issue</th><th>Severity</th><th>Before</th><th>After</th><th>Delta</th><th>Reduction</th><th>Frameworks</th></tr></thead><tbody>${canonicalRows}</tbody></table>` : '<p>No canonical issue changes.</p>'}
${newRows ? `<h2>New Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${newRows}</tbody></table>` : '<p>No new findings.</p>'}
${resolvedRows ? `<h2>Resolved Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${resolvedRows}</tbody></table>` : ''}
</body></html>`;
}

export function deactivate() {}
