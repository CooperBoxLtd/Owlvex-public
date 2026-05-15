import * as fs from 'fs/promises';
import * as path from 'path';
import { execFile } from 'child_process';
import * as vscode from 'vscode';
import { ScanEngine, ScanResult } from './scanEngine';
import { PROFILE } from '../profile';

type ScanDirent = {
    name: string;
    isDirectory(): boolean;
    isFile(): boolean;
};

const SUPPORTED_EXTENSIONS = new Set([
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.mts', '.cts',
    '.py', '.java', '.cs', '.go',
    '.rs', '.php', '.rb', '.cpp',
    '.c', '.h',
]);

const SUPPORTED_MANIFEST_FILES = new Set([
    'package.json',
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

export interface ChangedFileSkip {
    path: string;
    reason: string;
}

export interface ChangedScannableFilesResult {
    files: vscode.Uri[];
    gitChangedPaths: string[];
    skipped: ChangedFileSkip[];
}

export interface GitTargetScannableFilesResult {
    files: vscode.Uri[];
    gitTarget: string;
    gitChangedPaths: string[];
    skipped: ChangedFileSkip[];
    errors: string[];
}

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

function isDeterministicOnlyCleanResult(result: ScanResult): boolean {
    return /\(deterministic-only\)/i.test(result.model)
        && result.findings.length === 0
        && (result.warnings ?? []).some(warning => /deterministic-only|AI provider unavailable|AI response unusable|backend unavailable/i.test(warning));
}

async function sleep(ms: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, ms));
}

function isScannableSourceUri(uri: vscode.Uri | undefined): uri is vscode.Uri {
    if (!uri?.fsPath) {
        return false;
    }
    const basename = path.basename(uri.fsPath).toLowerCase();
    return SUPPORTED_MANIFEST_FILES.has(basename)
        || SUPPORTED_EXTENSIONS.has(path.extname(uri.fsPath).toLowerCase());
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

async function runGit(root: vscode.Uri, args: string[]): Promise<string[]> {
    const stdout = await new Promise<string>((resolve, reject) => {
        execFile('git', ['-C', root.fsPath, ...args], {
            maxBuffer: 1024 * 1024 * 4,
            windowsHide: true,
        }, (error, output) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(String(output));
        });
    });
    return String(stdout)
        .split('\0')
        .map(item => item.trim())
        .filter(Boolean);
}

async function existingScannableGitPath(root: vscode.Uri, relativePath: string): Promise<vscode.Uri | undefined> {
    if (path.isAbsolute(relativePath)) return undefined;

    const normalizedPath = path.normalize(relativePath);
    if (normalizedPath === '..' || normalizedPath.startsWith(`..${path.sep}`)) {
        return undefined;
    }

    const uri = vscode.Uri.file(path.join(root.fsPath, normalizedPath));
    if (!isScannableSourceUri(uri)) return undefined;

    try {
        const stat = await fs.stat(uri.fsPath);
        return stat.isFile() ? uri : undefined;
    } catch {
        return undefined;
    }
}

function getUnsupportedChangedFileReason(relativePath: string): string {
    const basename = path.basename(relativePath).toLowerCase();
    const extension = path.extname(relativePath).toLowerCase();

    if (basename === 'package-lock.json' || basename === 'pnpm-lock.yaml' || basename === 'yarn.lock') {
        return 'lockfile; dependency/supply-chain scanning is separate from source scanning';
    }

    if (basename === '.gitignore' || basename === '.gitattributes') {
        return 'Git metadata; not scanned as application source';
    }

    if (extension === '.md' || extension === '.txt' || extension === '.pdf' || extension === '.docx') {
        return 'documentation/context file; use TDD Box or Design Box when it should ground a scan';
    }

    if (extension === '.json' || extension === '.yaml' || extension === '.yml' || extension === '.toml') {
        return 'configuration file; not currently scanned as source';
    }

    return 'unsupported file type for source scanning';
}

export async function collectChangedScannableFilesDetailed(root: vscode.Uri, limit = 200): Promise<ChangedScannableFilesResult> {
    let changedPaths: string[] = [];
    try {
        changedPaths = await runGit(root, ['diff', '--name-only', '-z', '--relative', '--diff-filter=ACMRTUXB', 'HEAD', '--', '.']);
    } catch {
        try {
            changedPaths = await runGit(root, ['diff', '--name-only', '-z', '--relative', '--diff-filter=ACMRTUXB', '--', '.']);
        } catch {
            return { files: [], gitChangedPaths: [], skipped: [] };
        }
    }

    let untrackedPaths: string[] = [];
    try {
        untrackedPaths = await runGit(root, ['ls-files', '--others', '--exclude-standard', '-z', '--', '.']);
    } catch {
        untrackedPaths = [];
    }

    const uniquePaths = [...new Set([...changedPaths, ...untrackedPaths])].slice(0, limit * 2);
    const files: vscode.Uri[] = [];
    const skipped: ChangedFileSkip[] = [];
    for (const relativePath of uniquePaths) {
        if (files.length >= limit) break;
        const uri = await existingScannableGitPath(root, relativePath);
        if (uri) {
            files.push(uri);
        } else {
            skipped.push({
                path: relativePath,
                reason: getUnsupportedChangedFileReason(relativePath),
            });
        }
    }

    return { files, gitChangedPaths: uniquePaths, skipped };
}

export async function collectChangedScannableFiles(root: vscode.Uri, limit = 200): Promise<vscode.Uri[]> {
    const result = await collectChangedScannableFilesDetailed(root, limit);
    return result.files;
}

function looksLikeGitRange(target: string): boolean {
    return /\.{2,3}/.test(target);
}

export async function collectGitTargetScannableFilesDetailed(root: vscode.Uri, gitTarget: string, limit = 200): Promise<GitTargetScannableFilesResult> {
    const target = gitTarget.trim();
    if (!target) {
        return { files: [], gitTarget: target, gitChangedPaths: [], skipped: [], errors: ['No Git commit, branch, tag, or range was provided.'] };
    }

    let changedPaths: string[] = [];
    try {
        changedPaths = looksLikeGitRange(target)
            ? await runGit(root, ['diff', '--name-only', '-z', '--relative', '--diff-filter=ACMRTUXB', target, '--', '.'])
            : await runGit(root, ['diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-z', '--diff-filter=ACMRTUXB', target, '--', '.']);
    } catch (error: any) {
        return {
            files: [],
            gitTarget: target,
            gitChangedPaths: [],
            skipped: [],
            errors: [`Git target could not be resolved locally: ${error.message}`],
        };
    }

    const uniquePaths = [...new Set(changedPaths)].slice(0, limit * 2);
    const files: vscode.Uri[] = [];
    const skipped: ChangedFileSkip[] = [];
    for (const relativePath of uniquePaths) {
        if (files.length >= limit) break;
        const uri = await existingScannableGitPath(root, relativePath);
        if (uri) {
            files.push(uri);
        } else {
            skipped.push({
                path: relativePath,
                reason: getUnsupportedChangedFileReason(relativePath),
            });
        }
    }

    return { files, gitTarget: target, gitChangedPaths: uniquePaths, skipped, errors: [] };
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
    const sharedDrift = typeof (options.scanEngine as any).prepareSharedDriftScanContext === 'function'
        ? await (options.scanEngine as any).prepareSharedDriftScanContext(files, 'scan')
        : undefined;

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
                        ? sharedDrift
                            ? await (options.scanEngine as any).scanDocumentsBatch(documents, { sharedDrift })
                            : await (options.scanEngine as any).scanDocumentsBatch(documents)
                        : [sharedDrift
                            ? await options.scanEngine.scanDocument(documents[0], {
                                driftBoxContext: sharedDrift.driftBoxContext,
                                driftResults: sharedDrift.driftResults,
                            })
                            : await options.scanEngine.scanDocument(documents[0])];

                    for (let batchIndex = 0; batchIndex < batchResults.length; batchIndex += 1) {
                        let batchResult = batchResults[batchIndex];
                        const batchUri = batchUris[batchIndex];
                        const batchDoc = documents[batchIndex];

                        if (shouldBatch && isDeterministicOnlyCleanResult(batchResult)) {
                            try {
                                const retryResult = await options.scanEngine.scanDocument(batchDoc, sharedDrift ? {
                                    driftBoxContext: sharedDrift.driftBoxContext,
                                    driftResults: sharedDrift.driftResults,
                                } : undefined);
                                if (!/\(deterministic-only\)/i.test(retryResult.model) || retryResult.findings.length > 0) {
                                    batchResult = {
                                        ...retryResult,
                                        warnings: [
                                            ...retryResult.warnings,
                                            'Batch AI retry: single-file AI scan replaced a clean deterministic-only batch result.',
                                        ],
                                    };
                                }
                            } catch (retryError: any) {
                                batchResult = {
                                    ...batchResult,
                                    warnings: [
                                        ...batchResult.warnings,
                                        `Batch AI retry failed: ${retryError.message}`,
                                    ],
                                };
                            }
                        }

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
