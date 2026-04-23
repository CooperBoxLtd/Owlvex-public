import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanEngine, ScanResult } from './scanEngine';
import { PROFILE } from '../profile';

type ScanDirent = {
    name: string;
    isDirectory(): boolean;
    isFile(): boolean;
};

const SUPPORTED_EXTENSIONS = new Set([
    '.ts', '.tsx', '.js', '.jsx',
    '.py', '.java', '.cs', '.go',
    '.rs', '.php', '.rb', '.cpp',
    '.c', '.h',
]);

const EXCLUDED_DIRS = new Set([
    '.git',
    'node_modules',
    'dist',
    'out',
    'vendor',
    '.next',
    '.turbo',
]);

const AI_BATCH_SIZE = 3;

const RATE_LIMIT_COOLDOWN_MS = 5000;
const MAX_RATE_LIMIT_COOLDOWN_MS = 60000;
const FOUNDRY_BATCH_STEADY_STATE_REQUEST_LIMIT = 7;

interface ProviderRateBudgetProfile {
    requestLimit: number;
    requestWindowMs: number;
    estimatedRequestsPerFile: number;
    steadyStateRequestLimit: number;
}

function getProviderRateBudgetProfile(provider: string | undefined, model: string | undefined): ProviderRateBudgetProfile | undefined {
    void model;

    if (provider !== 'azure-foundry') {
        return undefined;
    }

    // Foundry deployment names are customer-defined, so pacing cannot depend on
    // hardcoded deployment strings. Use a conservative provider-level profile
    // until deployment-specific limits are discoverable from metadata.
    return {
        requestLimit: 10,
        requestWindowMs: 60000,
        estimatedRequestsPerFile: 3,
        steadyStateRequestLimit: FOUNDRY_BATCH_STEADY_STATE_REQUEST_LIMIT,
    };
}

interface BatchRequestBudgetPlan {
    proactiveSpacingMs: number;
    estimatedDurationMs: number;
}

type ScanPacingMode = 'workspace' | 'interactive';

function getProactiveSpacingMs(
    profile: ProviderRateBudgetProfile | undefined,
): number {
    if (!profile) {
        return 0;
    }

    const filesPerWindow = Math.max(1, Math.floor(profile.steadyStateRequestLimit / Math.max(1, profile.estimatedRequestsPerFile)));
    return Math.ceil(profile.requestWindowMs / filesPerWindow);
}

function planBatchRequestBudget(
    fileCount: number,
    provider: string | undefined,
    model: string | undefined,
    pacingMode: ScanPacingMode,
): BatchRequestBudgetPlan {
    const profile = getProviderRateBudgetProfile(provider, model);
    if (!profile || fileCount <= 0) {
        return { proactiveSpacingMs: getProactiveSpacingMs(profile), estimatedDurationMs: 0 };
    }

    if (pacingMode === 'interactive' && fileCount <= AI_BATCH_SIZE) {
        return { proactiveSpacingMs: 0, estimatedDurationMs: 0 };
    }

    const proactiveSpacingMs = getProactiveSpacingMs(profile);
    return {
        proactiveSpacingMs,
        estimatedDurationMs: Math.max(0, (fileCount - 1) * proactiveSpacingMs),
    };
}

function extractRetryAfterMsFromWarnings(warnings: string[] = []): number | undefined {
    for (const warning of warnings) {
        const retryAfterSecondsMatch = warning.match(/retry-after:\s*(\d+(?:\.\d+)?)/i);
        if (retryAfterSecondsMatch) {
            return Math.max(0, Math.ceil(Number(retryAfterSecondsMatch[1]) * 1000));
        }

        const retryAfterMsMatch = warning.match(/retry-after-ms:\s*(\d+)/i);
        if (retryAfterMsMatch) {
            return Math.max(0, Number(retryAfterMsMatch[1]));
        }
    }

    return undefined;
}

async function sleep(ms: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, ms));
}

function isScannableSourceUri(uri: vscode.Uri | undefined): uri is vscode.Uri {
    return Boolean(uri?.fsPath && SUPPORTED_EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase()));
}

export function getActiveScannableEditorUri(): vscode.Uri | undefined {
    const activeUri = vscode.window.activeTextEditor?.document?.uri;
    return isScannableSourceUri(activeUri) ? activeUri : undefined;
}

export async function pickScanRoot(): Promise<vscode.Uri | undefined> {
    const picked = await vscode.window.showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: false,
        openLabel: 'Scan This Folder',
        title: 'Select folder to scan with Owlvex',
        defaultUri: vscode.workspace.workspaceFolders?.[0]?.uri,
    });

    return picked?.[0];
}

export async function pickScanFile(): Promise<vscode.Uri | undefined> {
    const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectFolders: false,
        canSelectMany: false,
        openLabel: 'Scan This File',
        title: 'Select file to scan with Owlvex',
        defaultUri: vscode.window.activeTextEditor?.document.uri ?? vscode.workspace.workspaceFolders?.[0]?.uri,
        filters: {
            'Source Files': ['ts', 'tsx', 'js', 'jsx', 'py', 'java', 'cs', 'go', 'rs', 'php', 'rb', 'cpp', 'c', 'h'],
        },
    });

    return picked?.[0];
}

export async function resolveScanFileTarget(requestedUri?: vscode.Uri): Promise<vscode.Uri | undefined> {
    if (isScannableSourceUri(requestedUri)) {
        return requestedUri;
    }

    const activeUri = getActiveScannableEditorUri();
    if (activeUri) {
        return activeUri;
    }

    return pickScanFile();
}

export async function pickScanFiles(): Promise<vscode.Uri[] | undefined> {
    const picked = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectFolders: false,
        canSelectMany: true,
        openLabel: 'Scan Selected Files',
        title: 'Select files to scan with Owlvex',
        defaultUri: vscode.window.activeTextEditor?.document.uri ?? vscode.workspace.workspaceFolders?.[0]?.uri,
        filters: {
            'Source Files': ['ts', 'tsx', 'js', 'jsx', 'py', 'java', 'cs', 'go', 'rs', 'php', 'rb', 'cpp', 'c', 'h'],
        },
    });

    return picked?.length ? picked : undefined;
}

export async function collectScannableFiles(root: vscode.Uri, limit = 500): Promise<vscode.Uri[]> {
    const files: vscode.Uri[] = [];

    async function walk(currentPath: string): Promise<void> {
        if (files.length >= limit) return;

        let entries: ScanDirent[];
        try {
            entries = await fs.readdir(currentPath, { withFileTypes: true, encoding: 'utf8' });
        } catch {
            return;
        }

        for (const entry of entries) {
            if (files.length >= limit) return;

            const fullPath = path.join(currentPath, entry.name);
            if (entry.isDirectory()) {
                if (EXCLUDED_DIRS.has(entry.name)) continue;
                await walk(fullPath);
                continue;
            }

            if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
                files.push(vscode.Uri.file(fullPath));
            }
        }
    }

    await walk(root.fsPath);
    return files;
}

export interface FolderScanFileResult {
    uri: vscode.Uri;
    result: ScanResult;
}

export interface FolderScanSummary {
    status: 'completed' | 'cancelled' | 'empty' | 'failed';
    completed: number;
    totalFindings: number;
    errors: string[];
    results: FolderScanFileResult[];
}

export async function scanFolder(options: {
    root: vscode.Uri;
    scanEngine: ScanEngine;
    diagnostics: { applyFindings(doc: vscode.TextDocument, findings: any[]): void };
    skipConfirmation?: boolean;
}): Promise<FolderScanSummary> {
    const files = await collectScannableFiles(options.root);
    if (!files.length) {
        vscode.window.showInformationMessage('No supported source files found in the selected folder');
        return { status: 'empty', completed: 0, totalFindings: 0, errors: [], results: [] };
    }

    return scanUris({
        files,
        scanEngine: options.scanEngine,
        diagnostics: options.diagnostics,
        pacingMode: 'workspace',
        confirmLabel: 'Scan Folder',
        confirmMessage: `Owlvex: Scan ${files.length} file(s) in ${path.basename(options.root.fsPath)}?`,
        progressTitle: `Owlvex: Scanning ${path.basename(options.root.fsPath)}`,
        getShortName: (uri) => path.relative(options.root.fsPath, uri.fsPath) || path.basename(uri.fsPath),
        skipConfirmation: options.skipConfirmation,
    });
}

export async function scanSelectedFiles(options: {
    files: vscode.Uri[];
    scanEngine: ScanEngine;
    diagnostics: { applyFindings(doc: vscode.TextDocument, findings: any[]): void };
    skipConfirmation?: boolean;
}): Promise<FolderScanSummary> {
    if (!options.files.length) {
        vscode.window.showInformationMessage('No supported source files were selected');
        return { status: 'empty', completed: 0, totalFindings: 0, errors: [], results: [] };
    }

    return scanUris({
        files: options.files,
        scanEngine: options.scanEngine,
        diagnostics: options.diagnostics,
        pacingMode: 'interactive',
        confirmLabel: 'Scan Selected Files',
        confirmMessage: `Owlvex: Scan ${options.files.length} selected file(s)?`,
        progressTitle: 'Owlvex: Scanning selected files',
        getShortName: (uri) => vscode.workspace.asRelativePath(uri, false) || path.basename(uri.fsPath),
        skipConfirmation: options.skipConfirmation,
    });
}

async function scanUris(options: {
    files: vscode.Uri[];
    scanEngine: ScanEngine;
    diagnostics: { applyFindings(doc: vscode.TextDocument, findings: any[]): void };
    pacingMode: ScanPacingMode;
    confirmLabel: string;
    confirmMessage: string;
    progressTitle: string;
    getShortName: (uri: vscode.Uri) => string;
    skipConfirmation?: boolean;
}): Promise<FolderScanSummary> {
    const files = options.files;

    if (!options.skipConfirmation) {
        const confirm = await vscode.window.showInformationMessage(
            options.confirmMessage,
            { modal: true },
            options.confirmLabel,
        );
        if (confirm !== options.confirmLabel) {
            return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
        }
    }

    let completed = 0;
    let totalFindings = 0;
    const errors: string[] = [];
    const results: FolderScanFileResult[] = [];
    let cancelled = false;
    let cooldownUntil = 0;
    let consecutiveRateLimitHits = 0;
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const provider = config.get<string>('provider');
    const modelSettingKey = provider === 'azure-foundry'
        ? 'foundry.model'
        : provider
            ? `${provider}.model`
            : undefined;
    const model = modelSettingKey ? config.get<string>(modelSettingKey) : undefined;
    const batchBudgetPlan = planBatchRequestBudget(files.length, provider, model, options.pacingMode);
    let proactiveBudgetUntil = 0;

    if (batchBudgetPlan.proactiveSpacingMs > 0 && files.length > 1) {
        proactiveBudgetUntil = Date.now() + batchBudgetPlan.proactiveSpacingMs;
        const estimatedSeconds = Math.ceil(batchBudgetPlan.estimatedDurationMs / 1000);
        vscode.window.showInformationMessage(
            `${PROFILE.displayLabel}: Full AI scan will be paced to stay within provider quota. Estimated additional wait: about ${estimatedSeconds}s.`,
        );
    }

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: options.progressTitle,
            cancellable: true,
        },
        async (progress, token) => {
            for (let fileIndex = 0; fileIndex < files.length; fileIndex += 1) {
                const uri = files[fileIndex];
                if (token.isCancellationRequested) {
                    cancelled = true;
                    break;
                }

                const remainingCooldownMs = Math.max(cooldownUntil, proactiveBudgetUntil) - Date.now();
                if (remainingCooldownMs > 0) {
                    progress.report({
                        message: cooldownUntil >= proactiveBudgetUntil
                            ? `Provider rate limit hit. Cooling down for ${Math.ceil(remainingCooldownMs / 1000)}s before continuing...`
                            : `Applying provider request budget. Waiting ${Math.ceil(remainingCooldownMs / 1000)}s before continuing...`,
                    });
                    await sleep(remainingCooldownMs);
                }

                const attemptedIndex = completed + errors.length + 1;
                const shortName = options.getShortName(uri);
                progress.report({
                    message: `${shortName} (${attemptedIndex}/${files.length})`,
                    increment: (1 / files.length) * 100,
                });

                try {
                    const remainingFiles = files.slice(fileIndex);
                    const shouldBatch = typeof (options.scanEngine as any).scanDocumentsBatch === 'function' && remainingFiles.length > 1;
                    const batchUris = shouldBatch ? remainingFiles.slice(0, AI_BATCH_SIZE) : [uri];
                    const documents = await Promise.all(batchUris.map(batchUri => vscode.workspace.openTextDocument(batchUri)));
                    const batchResults: ScanResult[] = shouldBatch
                        ? await (options.scanEngine as any).scanDocumentsBatch(documents)
                        : [await options.scanEngine.scanDocument(documents[0])];

                    for (let batchIndex = 0; batchIndex < batchResults.length; batchIndex += 1) {
                        const batchResult = batchResults[batchIndex];
                        const batchUri = batchUris[batchIndex];
                        const batchDoc = documents[batchIndex];

                        if ((batchResult.warnings ?? []).some(warning => /\b429\b|rate limit/i.test(warning))) {
                            consecutiveRateLimitHits += 1;
                            const providerRetryAfterMs = extractRetryAfterMsFromWarnings(batchResult.warnings);
                            const adaptiveCooldownMs = Math.min(
                                MAX_RATE_LIMIT_COOLDOWN_MS,
                                RATE_LIMIT_COOLDOWN_MS * (2 ** Math.max(0, consecutiveRateLimitHits - 1)),
                            );
                            cooldownUntil = Date.now() + Math.max(adaptiveCooldownMs, providerRetryAfterMs ?? 0);
                        } else {
                            consecutiveRateLimitHits = 0;
                            cooldownUntil = 0;
                        }

                        const proactiveSpacingMs = batchBudgetPlan.proactiveSpacingMs || getProactiveSpacingMs(
                            getProviderRateBudgetProfile(batchResult.provider, batchResult.model),
                        );
                        proactiveBudgetUntil = proactiveSpacingMs > 0
                            ? Date.now() + proactiveSpacingMs
                            : 0;
                        options.diagnostics.applyFindings(batchDoc, batchResult.findings);
                        totalFindings += batchResult.findings.length;
                        results.push({ uri: batchUri, result: batchResult });
                        completed++;
                    }

                    if (shouldBatch) {
                        fileIndex += batchUris.length - 1;
                        continue;
                    }
                } catch (error: any) {
                    errors.push(`${shortName}: ${error.message}`);
                }
            }
        },
    );

    return {
        status: cancelled
            ? 'cancelled'
            : completed === 0 && errors.length > 0
                ? 'failed'
                : 'completed',
        completed,
        totalFindings,
        errors,
        results,
    };
}
