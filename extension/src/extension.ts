import * as vscode from 'vscode';
import * as path from 'path';
import { LicenceManager } from './licence/licenceManager';
import { getProviderApiKeySecretName, ProviderRegistry, persistProviderSetting } from './providers/registry';
import { ScanEngine, ScanResult } from './scanner/scanEngine';
import { DiagnosticsProvider } from './diagnostics/diagnosticsProvider';
import { StatusBar } from './ui/statusBar';
import { SidebarProvider } from './panels/sidebarProvider';
import { ChatViewProvider } from './panels/chatViewProvider';
import { buildRiskCalibrationReport, StoredScanRecord } from './scanner/calibrationReview';
import { pickScanFile, pickScanFiles, pickScanRoot, scanFolder, scanSelectedFiles } from './scanner/workspaceScanner';
import { generateReportFromSnapshot, ReportSnapshot } from './scanner/reportGenerator';
import { FRAMEWORK_CATALOG, formatFrameworkSummary } from './frameworks/catalog';
import { configureRulePackRuntime } from './frameworks/rulePackRegistry';
import { PROFILE } from './profile';
import { initializeSecretStorage } from './secrets';
import { PackArtifactResponse, PackEntitlement, PackManifestEntry, RulePackClient } from './packs/packClient';
import { RulePackRuntimeContext } from './packs/packRuntime';

export let secrets: vscode.SecretStorage;

const MAX_STORED_SCANS = 20;
const scanStore = new Map<string, StoredScanRecord>();
const SCAN_STORE_KEY = `${PROFILE.storagePrefix}.scanStore`;
const LAST_REPORT_SNAPSHOT_KEY = `${PROFILE.storagePrefix}.lastReportSnapshot`;
const ISSUE_PACK_ID = 'owlvex.issue-pack.v1';
const ISSUE_MAPPING_PACK_ID = 'owlvex.issue-mapping-pack.v1';
const REMEDIATION_PACK_ID = 'owlvex.remediation-pack.v1';

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

interface ScanSelectedFilesCommandResult {
    status: 'completed' | 'cancelled' | 'empty';
    files?: vscode.Uri[];
    completed: number;
    totalFindings: number;
    errors: string[];
    results: Array<{ uri: vscode.Uri; result: ScanResult }>;
}

interface ScanOpenEditorsCommandResult {
    status: 'completed' | 'cancelled' | 'empty';
    files?: vscode.Uri[];
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

function storeScanResult(scanId: string, result: ScanResult, targetLabel?: string): void {
    if (scanStore.size >= MAX_STORED_SCANS) {
        const firstKey = scanStore.keys().next().value;
        if (firstKey) scanStore.delete(firstKey);
    }
    scanStore.set(scanId, normalizeStoredScanRecord({
        scanId,
        result,
        targetLabel,
        scannedAt: new Date().toISOString(),
    }));
}

function serializeScanStore(): StoredScanRecord[] {
    return Array.from(scanStore.values()).map(item => ({
        ...item,
        result: normalizeScanResult(item.result),
    }));
}

function normalizeScanResult(result: ScanResult): ScanResult {
    return {
        ...result,
        warnings: result.warnings ?? [],
    };
}

function normalizeStoredScanRecord(item: { scanId: string; result: ScanResult; targetLabel?: string; scannedAt?: string }): StoredScanRecord {
    return {
        scanId: item.scanId,
        result: normalizeScanResult(item.result),
        targetLabel: item.targetLabel,
        scannedAt: item.scannedAt,
    };
}

function collectOpenEditorUris(): vscode.Uri[] {
    const seen = new Map<string, vscode.Uri>();
    for (const document of vscode.workspace.textDocuments) {
        if (document.uri.scheme !== 'file') {
            continue;
        }

        const ext = path.extname(document.uri.fsPath).toLowerCase();
        if (!['.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.cpp', '.c', '.h'].includes(ext)) {
            continue;
        }

        seen.set(document.uri.fsPath, document.uri);
    }

    return [...seen.values()];
}

function getFrameworkConfigurationTarget(): vscode.ConfigurationTarget {
    return vscode.workspace.workspaceFolders?.length
        ? vscode.ConfigurationTarget.Workspace
        : vscode.ConfigurationTarget.Global;
}

function normalizeServiceUrl(value: string): string {
    return value.trim().replace(/\/+$/, '');
}

function isLikelyAzureFoundryEndpoint(value: string): boolean {
    const normalized = normalizeServiceUrl(value);
    return /^https:\/\/[A-Za-z0-9-]+\.(openai\.azure\.com|services\.ai\.azure\.com)$/i.test(normalized);
}

function getProviderSetupSummary(providerId: string): string {
    switch (providerId) {
        case 'azure-foundry':
            return 'Paste the Azure endpoint, the deployment name you created in Azure AI Foundry, and the API key from Keys and Endpoint.';
        case 'custom':
            return 'Provide the base URL, the exact model name, and an API key if your endpoint requires one.';
        case 'ollama':
            return 'Provide the Ollama host URL and the local model name installed on that host.';
        case 'anthropic':
            return 'Provide the API key and the exact Claude model name you want Owlvex to use.';
        default:
            return 'Provide the API key and, when applicable, the exact model name you want Owlvex to use.';
    }
}

async function testCurrentProviderConnection(registry: ProviderRegistry): Promise<{ success: boolean; latencyMs: number; message?: string; providerName: string; model: string }> {
    const provider = registry.getActive();
    const result = await provider.testConnection();
    return {
        ...result,
        providerName: provider.name,
        model: provider.selectedModel,
    };
}

async function promptForSetting(
    settingKey: string,
    prompt: string,
    placeHolder: string,
    validateInput?: (value: string) => string | undefined,
): Promise<string | undefined> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const current = config.get<string>(settingKey, '');
    const value = await vscode.window.showInputBox({
        prompt,
        placeHolder,
        value: current,
        ignoreFocusOut: true,
        validateInput,
    });

    if (!value) {
        return undefined;
    }

    const normalized = settingKey.endsWith('endpoint') || settingKey.endsWith('baseUrl')
        ? normalizeServiceUrl(value)
        : value.trim();
    await persistProviderSetting(settingKey, normalized);
    return normalized;
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
    initializeSecretStorage(context.secrets);

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const apiUrl = config.get<string>('apiUrl') ?? PROFILE.defaultApiUrl;

    const licenceMgr = new LicenceManager(context.secrets);
    const registry = new ProviderRegistry();
    const scanEngine = new ScanEngine(licenceMgr, registry);
    const rulePackClient = new RulePackClient(context.workspaceState);
    let currentRulePackContext: RulePackRuntimeContext = {
        mode: 'bundled',
        packIds: [],
    };
    const diagnostics = new DiagnosticsProvider();
    const statusBar = new StatusBar();
    const sidebar = new SidebarProvider();
    const restoredScans = context.workspaceState.get<Array<{ scanId: string; result: ScanResult; targetLabel?: string; scannedAt?: string }>>(SCAN_STORE_KEY, []);
    for (const item of restoredScans) {
        scanStore.set(item.scanId, normalizeStoredScanRecord(item));
    }
    const lastStoredScan = restoredScans[restoredScans.length - 1]?.result;
    if (lastStoredScan) {
        sidebar.refresh(lastStoredScan);
    }

    const persistScans = async () => {
        await context.workspaceState.update(SCAN_STORE_KEY, serializeScanStore());
    };

    const currentEntitlement = (): PackEntitlement | undefined => {
        const info = licenceMgr.getCachedInfo();
        if (!info) {
            return undefined;
        }

        return {
            plan: info.plan,
            frameworks: info.features.frameworks,
        };
    };

    const applyRulePackContext = (result: ScanResult): ScanResult => ({
        ...result,
        packContext: {
            ...currentRulePackContext,
            packIds: [...currentRulePackContext.packIds],
        },
    });

    const isRevocationLikeError = (error: unknown): boolean => {
        const message = String((error as any)?.message ?? '').toLowerCase();
        return [
            'licence key not found',
            'licence is inactive',
            'licence has expired',
            'http 401',
            'http 403',
        ].some(fragment => message.includes(fragment));
    };

    const purgeRulePackState = async () => {
        await rulePackClient.purgeCachedRulePacks();
        configureRulePackRuntime(undefined, undefined);
        currentRulePackContext = {
            mode: 'bundled',
            packIds: [],
        };
    };

    const hydrateRulePackRuntimeFromCache = (entitlement?: PackEntitlement) => {
        const manifestFreshness = rulePackClient.getCachedManifestFreshness(entitlement);
        const cachedIssuePack = rulePackClient.getCachedPack(ISSUE_PACK_ID, entitlement);
        const cachedMappingPack = rulePackClient.getCachedPack(ISSUE_MAPPING_PACK_ID, entitlement);
        const cachedRemediationPack = rulePackClient.getCachedPack(REMEDIATION_PACK_ID, entitlement);
        configureRulePackRuntime(cachedIssuePack?.artifact, cachedMappingPack?.artifact, cachedRemediationPack?.artifact);
        currentRulePackContext = cachedIssuePack && cachedMappingPack
            ? {
                mode: 'cached',
                packIds: [ISSUE_PACK_ID, ISSUE_MAPPING_PACK_ID, ...(cachedRemediationPack ? [REMEDIATION_PACK_ID] : [])],
                fetchedAt: cachedIssuePack.fetched_at ?? cachedMappingPack.fetched_at ?? cachedRemediationPack?.fetched_at,
                manifestFreshness: manifestFreshness === 'missing' ? 'stale' : manifestFreshness,
            }
            : {
                mode: 'bundled',
                packIds: [],
            };
    };

    const refreshRulePackRuntime = async () => {
        const licenceKey = await licenceMgr.getKey();
        if (!licenceKey) {
            hydrateRulePackRuntimeFromCache();
            return;
        }

        const entitlement = currentEntitlement();

        let manifest;
        try {
            manifest = await rulePackClient.syncManifest(apiUrl, licenceKey);
        } catch (error) {
            if (isRevocationLikeError(error)) {
                await purgeRulePackState();
            } else {
                hydrateRulePackRuntimeFromCache(entitlement);
            }
            return;
        }

        const requiredPackIds = new Set([ISSUE_PACK_ID, ISSUE_MAPPING_PACK_ID, REMEDIATION_PACK_ID]);
        const manifestById = new Map<string, PackManifestEntry>(
            manifest.packs
                .filter(entry => requiredPackIds.has(entry.pack_id))
                .map(entry => [entry.pack_id, entry]),
        );

        const fetchIfListed = async (packId: string): Promise<{ artifact?: PackArtifactResponse; source: 'fresh' | 'cached' | 'missing' }> => {
            const entry = manifestById.get(packId);
            if (!entry) {
                return {
                    artifact: rulePackClient.getCachedPack(packId, entitlement),
                    source: rulePackClient.getCachedPack(packId, entitlement) ? 'cached' : 'missing',
                };
            }

            try {
                return {
                    artifact: await rulePackClient.fetchPackArtifact(apiUrl, licenceKey, entry),
                    source: 'fresh',
                };
            } catch {
                const cached = rulePackClient.getCachedPack(packId, entitlement);
                return {
                    artifact: cached,
                    source: cached ? 'cached' : 'missing',
                };
            }
        };

        const [issuePackResult, mappingPackResult, remediationPackResult] = await Promise.all([
            fetchIfListed(ISSUE_PACK_ID),
            fetchIfListed(ISSUE_MAPPING_PACK_ID),
            fetchIfListed(REMEDIATION_PACK_ID),
        ]);
        const issuePack = issuePackResult.artifact;
        const mappingPack = mappingPackResult.artifact;
        const remediationPack = remediationPackResult.artifact;

        configureRulePackRuntime(issuePack?.artifact, mappingPack?.artifact, remediationPack?.artifact);
        currentRulePackContext = issuePack && mappingPack
            ? {
                mode: issuePackResult.source === 'fresh'
                    && mappingPackResult.source === 'fresh'
                    && (!remediationPack || remediationPackResult.source === 'fresh')
                    ? 'fresh'
                    : 'cached',
                packIds: [ISSUE_PACK_ID, ISSUE_MAPPING_PACK_ID, ...(remediationPack ? [REMEDIATION_PACK_ID] : [])],
                fetchedAt: manifest.fetched_at,
                manifestFreshness: 'fresh',
            }
            : {
                mode: 'bundled',
                packIds: [],
            };
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
        const packContext = safeSnapshot.results[0]?.result.packContext;
        const averageScore = safeSnapshot.results.length
            ? safeSnapshot.results.reduce((total, item) => total + item.result.score, 0) / safeSnapshot.results.length
            : 0;
        const totalFindings = safeSnapshot.results.reduce((total, item) => total + item.result.findings.length, 0);
        const warningCount = safeSnapshot.results.reduce((total, item) => total + (item.result.warnings ?? []).length, 0);

        statusBar.showResult({
            score: averageScore,
            model: modelNames,
            findings: safeSnapshot.results.flatMap(item => item.result.findings),
            packContext,
        });
        vscode.window.showInformationMessage(
            `${PROFILE.displayLabel}: Report created for ${safeSnapshot.results.length} file(s) with ${totalFindings} finding(s) using ${providerNames}/${modelNames}.${warningCount ? ` ${warningCount} warning(s) were captured.` : ''}`
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
    hydrateRulePackRuntimeFromCache();

    vscode.window.registerTreeDataProvider(PROFILE.findingsViewId, sidebar);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(ChatViewProvider.viewType, chatView)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.discussFinding, async (finding?: any) => {
            if (!finding) {
                await chatView.show();
                return;
            }

            await chatView.discussFinding(finding);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.generateFixPreview, async (finding?: any) => {
            if (!finding) {
                await chatView.show();
                return;
            }

            await chatView.generateFixPreview(finding);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.applyFixPreview, async () => {
            await chatView.applyPendingFixPreview();
        })
    );

    licenceMgr.validate(apiUrl).then(() => {
        statusBar.showIdle();
        void refreshRulePackRuntime();
    }).catch(async (error) => {
        if (isRevocationLikeError(error)) {
            licenceMgr.clearCachedInfo();
            await purgeRulePackState();
        } else {
            hydrateRulePackRuntimeFromCache();
        }
        statusBar.showUnlicensed();
    });

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.enterLicence, async () => {
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
                    `${PROFILE.displayLabel} activated - ${info.plan} plan (${info.teamName})`
                );
                statusBar.showIdle();
                void refreshRulePackRuntime();
            } catch (error: any) {
                if (isRevocationLikeError(error)) {
                    licenceMgr.clearCachedInfo();
                    await purgeRulePackState();
                }
                vscode.window.showErrorMessage(`Licence validation failed: ${error.message}`);
                statusBar.showUnlicensed();
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.selectFrameworks, async () => {
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
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: No frameworks are available for this licence.`);
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
                vscode.window.showWarningMessage(`${PROFILE.displayLabel}: Select at least one framework.`);
                return;
            }

            const selectedCodes = picked.map(item => item.label);
            await vscode.workspace
                .getConfiguration(PROFILE.configSection)
                .update('frameworks', selectedCodes, getFrameworkConfigurationTarget());

            vscode.window.showInformationMessage(
                `${PROFILE.displayLabel}: Frameworks set to ${formatFrameworkSummary(selectedCodes)}`
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanFile, async (requestedUri?: vscode.Uri): Promise<ScanFileCommandResult> => {
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
                const result = applyRulePackContext(await scanEngine.scanDocument(editor.document));
                storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(editor.document.uri, false));
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(editor.document.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(editor.document.uri.fsPath)),
                    errors: [],
                    results: [{ uri: editor.document.uri, result }],
                });
                diagnostics.applyFindings(editor.document, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result);
                chatView.setLastScanTarget(`File: ${vscode.workspace.asRelativePath(editor.document.uri, false)}`);

                vscode.window.showInformationMessage(
                    `${PROFILE.displayLabel}: Score ${result.score.toFixed(1)}/10 - ${result.findings.length} finding(s)${(result.warnings ?? []).length ? ` (${(result.warnings ?? []).length} warning(s))` : ''}`
                );

                return { status: 'completed', uri: editor.document.uri, result };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanSelectedFiles, async (requestedUris?: vscode.Uri[] | vscode.Uri): Promise<ScanSelectedFilesCommandResult> => {
            const normalizedRequested = Array.isArray(requestedUris)
                ? requestedUris
                : requestedUris
                    ? [requestedUris]
                    : undefined;
            const fileUris = normalizedRequested?.length ? normalizedRequested : await pickScanFiles();
            if (!fileUris?.length) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            statusBar.showScanning();
            diagnostics.clear();
            sidebar.clear();

            try {
                const summary = await scanSelectedFiles({
                    files: fileUris,
                    scanEngine,
                    diagnostics,
                });
                const enrichedResults = summary.results.map(item => ({
                    uri: item.uri,
                    result: applyRulePackContext(item.result),
                }));
                const totalFindings = enrichedResults.reduce((total, item) => total + item.result.findings.length, 0);
                for (const item of enrichedResults) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (enrichedResults.length) {
                    const topResult = enrichedResults
                        .slice()
                        .sort((left, right) => right.result.score - left.result.score)[0];
                    sidebar.refresh(topResult.result);
                    statusBar.showResult(topResult.result);
                    chatView.setLastScanTarget(`Selected files: ${enrichedResults.length} file(s)`);
                } else {
                    statusBar.showIdle();
                }

                if (summary.status === 'completed' && enrichedResults.length) {
                    await persistLastReportSnapshot({
                        targetLabel: `${enrichedResults.length} selected file(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(enrichedResults[0].uri.fsPath)),
                        errors: summary.errors,
                        results: enrichedResults,
                    });
                    vscode.window.showInformationMessage(
                        `${PROFILE.displayLabel}: Scanned ${enrichedResults.length} selected file(s) with ${totalFindings} finding(s)${summary.errors.length ? ` (${summary.errors.length} error(s))` : ''}`
                    );
                } else if (summary.status === 'empty') {
                    vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No supported source files were selected.`);
                }

                return {
                    status: summary.status,
                    files: fileUris,
                    completed: summary.completed,
                    totalFindings,
                    errors: summary.errors,
                    results: enrichedResults,
                };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} selected-files scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanOpenEditors, async (): Promise<ScanOpenEditorsCommandResult> => {
            const fileUris = collectOpenEditorUris();
            if (!fileUris.length) {
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: No supported open editors were available to scan.`);
                return { status: 'empty', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            statusBar.showScanning();
            diagnostics.clear();
            sidebar.clear();

            try {
                const summary = await scanSelectedFiles({
                    files: fileUris,
                    scanEngine,
                    diagnostics,
                });
                const enrichedResults = summary.results.map(item => ({
                    uri: item.uri,
                    result: applyRulePackContext(item.result),
                }));
                const totalFindings = enrichedResults.reduce((total, item) => total + item.result.findings.length, 0);
                for (const item of enrichedResults) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
                }
                await persistScans();

                if (enrichedResults.length) {
                    const topResult = enrichedResults
                        .slice()
                        .sort((left, right) => right.result.score - left.result.score)[0];
                    sidebar.refresh(topResult.result);
                    statusBar.showResult(topResult.result);
                    chatView.setLastScanTarget(`Open editors: ${enrichedResults.length} file(s)`);
                    await persistLastReportSnapshot({
                        targetLabel: `${enrichedResults.length} open editor(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(enrichedResults[0].uri.fsPath)),
                        errors: summary.errors,
                        results: enrichedResults,
                    });
                } else {
                    statusBar.showIdle();
                }

                if (summary.status === 'completed' && enrichedResults.length) {
                    vscode.window.showInformationMessage(
                        `${PROFILE.displayLabel}: Scanned ${enrichedResults.length} open editor(s) with ${totalFindings} finding(s)${summary.errors.length ? ` (${summary.errors.length} error(s))` : ''}`
                    );
                }

                return {
                    status: summary.status,
                    files: fileUris,
                    completed: summary.completed,
                    totalFindings,
                    errors: summary.errors,
                    results: enrichedResults,
                };
            } catch (error: any) {
                statusBar.showError(error.message);
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} open-editors scan failed: ${error.message}`);
                throw error;
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc: vscode.TextDocument) => {
            const cfg = vscode.workspace.getConfiguration(PROFILE.configSection);
            if (!cfg.get<boolean>('scanOnSave', false)) return;

            statusBar.showScanning();
            try {
                const result = applyRulePackContext(await scanEngine.scanDocument(doc));
                storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(doc.uri, false));
                await persistScans();
                await persistLastReportSnapshot({
                    targetLabel: vscode.workspace.asRelativePath(doc.uri, false),
                    outputRoot: vscode.Uri.file(path.dirname(doc.uri.fsPath)),
                    errors: [],
                    results: [{ uri: doc.uri, result }],
                });
                diagnostics.applyFindings(doc, result.findings);
                sidebar.refresh(result);
                statusBar.showResult(result);
                chatView.setLastScanTarget(`Saved file: ${vscode.workspace.asRelativePath(doc.uri, false)}`);
            } catch (error: any) {
                statusBar.showError(error.message);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.switchModel, async () => {
            const provider = registry.getActive();
            const models = await provider.listModels();
            const picked = await vscode.window.showQuickPick(models, {
                placeHolder: `Select model (current: ${provider.selectedModel})`,
            });

            if (picked) {
                provider.selectedModel = picked;
                vscode.window.showInformationMessage(`${PROFILE.displayLabel}: Model switched to ${picked}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.setupAI, async () => {
            const currentProvider = registry.getActive();
            const providerChoice = await vscode.window.showQuickPick(
                registry.allProviders().map(item => ({
                    label: item.name,
                    description: item.id === currentProvider.id ? 'Current provider' : '',
                    providerId: item.id,
                })),
                {
                    placeHolder: 'Choose the LLM provider to configure',
                    ignoreFocusOut: true,
                },
            );
            if (!providerChoice) {
                return;
            }

            await registry.setActiveProvider(providerChoice.providerId);
            const provider = registry.getActive();
            if (provider.id === 'ollama') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const host = await promptForSetting(
                    'ollama.host',
                    'Enter the Ollama host URL',
                    'http://localhost:11434',
                    (value) => value.trim() ? undefined : 'The Ollama host is required.',
                );
                if (!host) {
                    return;
                }

                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the Ollama model name',
                    placeHolder: 'For example: qwen2.5:7b',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The Ollama model name is required.',
                });
                if (!model) {
                    return;
                }

                provider.selectedModel = model.trim();
                const { success, latencyMs } = await provider.testConnection();
                if (success) {
                    vscode.window.showInformationMessage(`Ollama connected (${latencyMs}ms) using ${provider.selectedModel} at ${host}`);
                } else {
                    vscode.window.showErrorMessage('Ollama connection failed. Check the host URL, confirm Ollama is running, and verify the model is installed.');
                }
                return;
            }

            if (provider.id === 'azure-foundry') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const endpoint = await promptForSetting(
                    'foundry.endpoint',
                    'Enter the Azure AI Foundry endpoint for this environment',
                    'https://your-resource.openai.azure.com',
                    (value) => {
                        if (!value.trim()) return 'The Foundry endpoint is required.';
                        return isLikelyAzureFoundryEndpoint(value)
                            ? undefined
                            : 'Use the Azure endpoint from Keys and Endpoint, for example https://your-resource.openai.azure.com';
                    },
                );
                if (!endpoint) {
                    return;
                }

                const deployment = await vscode.window.showInputBox({
                    prompt: 'Enter the Azure AI Foundry deployment name',
                    placeHolder: 'Use the deployment name you created in Azure AI Foundry, for example: owlvex-gpt4o',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The deployment name is required.',
                });
                if (!deployment) {
                    return;
                }

                await persistProviderSetting('foundry.model', deployment.trim());
            }

            if (provider.id === 'anthropic') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the Anthropic model name',
                    placeHolder: 'For example: claude-sonnet-4-6',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The model name is required.',
                });
                if (!model) {
                    return;
                }

                provider.selectedModel = model.trim();
            }

            if (provider.id === 'openai' || provider.id === 'gemini' || provider.id === 'mistral' || provider.id === 'groq') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const model = await vscode.window.showInputBox({
                    prompt: `Enter the ${provider.name} model name`,
                    placeHolder: `For example: ${provider.selectedModel}`,
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The model name is required.',
                });
                if (!model) {
                    return;
                }

                provider.selectedModel = model.trim();
            }

            if (provider.id === 'custom') {
                vscode.window.showInformationMessage(getProviderSetupSummary(provider.id));
                const baseUrl = await promptForSetting(
                    'custom.baseUrl',
                    'Enter the base URL for your OpenAI-compatible endpoint',
                    'https://api.example.com',
                    (value) => value.trim() ? undefined : 'The custom endpoint URL is required.',
                );
                if (!baseUrl) {
                    return;
                }

                const model = await vscode.window.showInputBox({
                    prompt: 'Enter the model name for the custom endpoint',
                    placeHolder: 'For example: my-custom-model',
                    value: provider.selectedModel,
                    ignoreFocusOut: true,
                    validateInput: (value) => value.trim() ? undefined : 'The custom model name is required.',
                });
                if (!model) {
                    return;
                }

                await persistProviderSetting('custom.model', model.trim());
            }

            const key = await vscode.window.showInputBox({
                prompt: `Enter API key for ${provider.name}`,
                ignoreFocusOut: true,
                password: true,
            });
            if (!key) return;

            await context.secrets.store(getProviderApiKeySecretName(provider.id), key);
            const { success, latencyMs, message } = await provider.testConnection();
            if (success) {
                try {
                    const models = await provider.listModels();
                    if (models.length && !models.includes(provider.selectedModel)) {
                        provider.selectedModel = models[0];
                    }
                    const activeModel = provider.selectedModel;
                    vscode.window.showInformationMessage(`${provider.name} connected (${latencyMs}ms) using ${activeModel}`);
                } catch {
                    vscode.window.showInformationMessage(`${provider.name} connected (${latencyMs}ms)`);
                }
            } else {
                const extraHint = provider.id === 'azure-foundry'
                    ? ' Check the endpoint, deployment name, and API key.'
                    : provider.id === 'custom'
                        ? ' Check the base URL, model name, and API key.'
                        : ' Check your key.';
                vscode.window.showErrorMessage(message?.trim() || `${provider.name} connection failed.${extraHint}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.testAI, async () => {
            const { success, latencyMs, message, providerName, model } = await testCurrentProviderConnection(registry);
            if (success) {
                vscode.window.showInformationMessage(`${providerName} is reachable (${latencyMs}ms) using ${model}`);
            } else {
                vscode.window.showErrorMessage(message?.trim() || `${providerName} connection failed. ${getProviderSetupSummary(registry.getActive().id)}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanWorkspace, async (requestedRoot?: vscode.Uri): Promise<ScanWorkspaceCommandResult> => {
            const root = requestedRoot ?? await pickScanRoot();
            if (!root) {
                return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
            }

            const summary = await scanFolder({
                root,
                scanEngine,
                diagnostics,
            });
            summary.results = summary.results.map(item => ({
                ...item,
                result: applyRulePackContext(item.result),
            }));

            for (const item of summary.results) {
                storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
            }
            await persistScans();
            await persistLastReportSnapshot({
                targetLabel: vscode.workspace.asRelativePath(root, false) || root.fsPath,
                outputRoot: root,
                errors: summary.errors,
                results: summary.results,
            });
            chatView.setLastScanTarget(`Folder: ${vscode.workspace.asRelativePath(root, false) || root.fsPath}`);

            const msg = `${PROFILE.displayLabel}: Scanned ${summary.completed} file(s) in ${root.fsPath} - ${summary.totalFindings} finding(s)`;
            if (summary.errors.length) {
                vscode.window.showWarningMessage(`${msg} (${summary.errors.length} error(s) - see output)`);
            } else if (summary.completed > 0) {
                vscode.window.showInformationMessage(msg);
            }

            return { root, ...summary };
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.scanWorkspaceReport, async (): Promise<ReportCommandResult> => {
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
                    { label: 'Scan selected files and create report', description: 'Pick multiple files, scan them, then create a report' },
                    { label: 'Scan open editors and create report', description: 'Scan currently open editors, then create a report' },
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

                    const result = applyRulePackContext(await scanEngine.scanDocument(document));
                    storeScanResult(result.scanId, result, vscode.workspace.asRelativePath(document.uri, false));
                    await persistScans();
                    diagnostics.applyFindings(document, result.findings);
                    sidebar.refresh(result);
                    statusBar.showResult(result);

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

                if (picked.label === 'Scan selected files and create report') {
                    const fileUris = await pickScanFiles();
                    if (!fileUris?.length) return { status: 'cancelled' };

                    statusBar.showScanning();
                    diagnostics.clear();
                    sidebar.clear();

                    const summary = await scanSelectedFiles({
                        files: fileUris,
                        scanEngine,
                        diagnostics,
                    });
                    summary.results = summary.results.map(item => ({
                        ...item,
                        result: applyRulePackContext(item.result),
                    }));

                    for (const item of summary.results) {
                        storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
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
                        targetLabel: `${summary.completed} selected file(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(summary.results[0].uri.fsPath)),
                        errors: summary.errors,
                        results: summary.results,
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report selected files: ${summary.completed} file(s)`);
                    return {
                        status: 'completed',
                        ...(await createAndOpenReport(snapshot)),
                    };
                }

                if (picked.label === 'Scan open editors and create report') {
                    const fileUris = collectOpenEditorUris();
                    if (!fileUris.length) {
                        return { status: 'empty' };
                    }

                    statusBar.showScanning();
                    diagnostics.clear();
                    sidebar.clear();

                    const summary = await scanSelectedFiles({
                        files: fileUris,
                        scanEngine,
                        diagnostics,
                    });
                    summary.results = summary.results.map(item => ({
                        ...item,
                        result: applyRulePackContext(item.result),
                    }));

                    for (const item of summary.results) {
                        storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
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
                        targetLabel: `${summary.completed} open editor(s)`,
                        outputRoot: vscode.Uri.file(path.dirname(summary.results[0].uri.fsPath)),
                        errors: summary.errors,
                        results: summary.results,
                    };
                    await persistLastReportSnapshot(snapshot);
                    chatView.setLastScanTarget(`Report open editors: ${summary.completed} file(s)`);
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
                summary.results = summary.results.map(item => ({
                    ...item,
                    result: applyRulePackContext(item.result),
                }));

                for (const item of summary.results) {
                    storeScanResult(item.result.scanId, item.result, vscode.workspace.asRelativePath(item.uri, false));
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
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} report failed: ${error.message}`);
                return { status: 'cancelled' };
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.openPromptEditor, async () => {
            await chatView.show();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.compareScans, async () => {
            const cfg = vscode.workspace.getConfiguration(PROFILE.configSection);
            const compareApiUrl = cfg.get<string>('apiUrl') ?? PROFILE.defaultApiUrl;
            const licenceKey = await licenceMgr.getKey();
            if (!licenceKey) {
                vscode.window.showErrorMessage('No licence key. Run "Owlvex: Enter Licence Key".');
                return;
            }

            const storedScans = Array.from(scanStore.values());
            if (storedScans.length < 2) {
                vscode.window.showWarningMessage(
                    'Owlvex: Need at least 2 scans in this session to compare. Scan a file or folder twice first.'
                );
                return;
            }

            const scanAChoice = await vscode.window.showQuickPick(storedScans.map(item => ({
                label: item.targetLabel || item.scanId,
                description: `${item.result.score.toFixed(1)}/10 | ${item.result.findings.length} finding(s)`,
                detail: item.scanId,
                record: item,
            })), {
                placeHolder: 'Select baseline scan (Scan A)',
            });
            if (!scanAChoice) return;

            const scanBChoice = await vscode.window.showQuickPick(
                storedScans
                    .filter(item => item.scanId !== scanAChoice.record.scanId)
                    .map(item => ({
                        label: item.targetLabel || item.scanId,
                        description: `${item.result.score.toFixed(1)}/10 | ${item.result.findings.length} finding(s)`,
                        detail: item.scanId,
                        record: item,
                    })),
                { placeHolder: 'Select comparison scan (Scan B)' },
            );
            if (!scanBChoice) return;

            const scanAId = scanAChoice.record.scanId;
            const scanBId = scanBChoice.record.scanId;
            const scanA = scanAChoice.record.result;
            const scanB = scanBChoice.record.result;

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
                    PROFILE.comparisonPanelId,
                    `${PROFILE.displayLabel}: Scan Comparison`,
                    vscode.ViewColumn.One,
                    {},
                );

                panel.webview.html = buildComparisonHtmlV2(diff, scoreChange);
            } catch (error: any) {
                vscode.window.showErrorMessage(`${PROFILE.displayLabel} compare failed: ${error.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.reviewRiskCalibration, async () => {
            const storedScans = Array.from(scanStore.values());
            if (!storedScans.length) {
                vscode.window.showWarningMessage('Owlvex: Run at least one scan before reviewing risk calibration.');
                return { status: 'empty', count: 0 };
            }

            const report = buildRiskCalibrationReport(storedScans);
            const document = await vscode.workspace.openTextDocument({
                language: 'markdown',
                content: report,
            });
            await vscode.window.showTextDocument(document, { preview: false });
            return { status: 'completed', count: storedScans.length };
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand(PROFILE.commands.revealLine, (line: number) => {
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
    const normalizedDiff = normalizeComparisonDiff(diff);
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = normalizedDiff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (normalizedDiff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (normalizedDiff.resolved_finding_details ?? []).map((f: any) =>
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
  <div class="stat"><div class="value negative">${normalizedDiff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${normalizedDiff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
</div>
${canonicalRows ? `<h2>Canonical Issue Changes</h2><table><thead><tr><th>Owlvex Issue</th><th>Severity</th><th>Before</th><th>After</th><th>Δ</th><th>Frameworks</th></tr></thead><tbody>${canonicalRows}</tbody></table>` : '<p>No canonical issue changes.</p>'}
${newRows ? `<h2>New Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${newRows}</tbody></table>` : '<p>No new findings.</p>'}
${resolvedRows ? `<h2>Resolved Findings</h2><table><thead><tr><th>Severity</th><th>Framework</th><th>Title</th><th>Line</th></tr></thead><tbody>${resolvedRows}</tbody></table>` : ''}
</body></html>`;
}

export function normalizeComparisonDiff(diff: any): any {
    const newFindingDetails = Array.isArray(diff?.new_finding_details)
        ? diff.new_finding_details
        : Array.isArray(diff?.new_findings)
            ? diff.new_findings
            : [];
    const resolvedFindingDetails = Array.isArray(diff?.resolved_finding_details)
        ? diff.resolved_finding_details
        : Array.isArray(diff?.resolved_findings)
            ? diff.resolved_findings
            : [];

    return {
        ...diff,
        new_findings: typeof diff?.new_findings === 'number' ? diff.new_findings : newFindingDetails.length,
        resolved_findings: typeof diff?.resolved_findings === 'number' ? diff.resolved_findings : resolvedFindingDetails.length,
        new_finding_details: newFindingDetails,
        resolved_finding_details: resolvedFindingDetails,
    };
}

function buildComparisonHtmlV2(diff: any, scoreChange: string): string {
    const normalizedDiff = normalizeComparisonDiff(diff);
    const severityWeight = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 4;
            case 'HIGH': return 3;
            case 'MEDIUM': return 2;
            case 'LOW': return 1;
            default: return 0;
        }
    };

    const canonicalChanges = normalizedDiff.canonical_changes ?? [];
    const weightedBefore = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_a ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedAfter = canonicalChanges.reduce((total: number, item: any) =>
        total + ((item.count_b ?? 0) * severityWeight(item.severity ?? '')), 0);
    const weightedImprovement = weightedBefore > 0
        ? Math.round(((weightedBefore - weightedAfter) / weightedBefore) * 100)
        : 0;

    const newRows = (normalizedDiff.new_finding_details ?? []).map((f: any) =>
        `<tr class="new"><td>${f.severity}</td><td>${f.framework}</td><td>${f.title}</td><td>L${f.line}</td></tr>`
    ).join('');
    const resolvedRows = (normalizedDiff.resolved_finding_details ?? []).map((f: any) =>
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
  <div class="support">Weighted exposure moved from ${weightedBefore} to ${weightedAfter}. ${normalizedDiff.resolved_findings ?? 0} findings were resolved and ${normalizedDiff.new_findings ?? 0} new findings were introduced.</div>
</div>
<div class="summary">
  <div class="stat"><div class="value ${Number(scoreChange) >= 0 ? 'positive' : 'negative'}">${scoreChange}</div><div class="label">Score Change</div></div>
  <div class="stat"><div class="value negative">${normalizedDiff.new_findings ?? 0}</div><div class="label">New Findings</div></div>
  <div class="stat"><div class="value positive">${normalizedDiff.resolved_findings ?? 0}</div><div class="label">Resolved</div></div>
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
