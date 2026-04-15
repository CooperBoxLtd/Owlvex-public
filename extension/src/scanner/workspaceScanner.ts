import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';
import { ScanEngine, ScanResult } from './scanEngine';

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

const RATE_LIMIT_COOLDOWN_MS = 5000;
const MAX_RATE_LIMIT_COOLDOWN_MS = 60000;
const AI_BUDGET_FALLBACK_THRESHOLD = 2;

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
        confirmLabel: 'Scan Folder',
        confirmMessage: `Owlvex: Scan ${files.length} file(s) in ${path.basename(options.root.fsPath)}?`,
        progressTitle: `Owlvex: Scanning ${path.basename(options.root.fsPath)}`,
        getShortName: (uri) => path.relative(options.root.fsPath, uri.fsPath) || path.basename(uri.fsPath),
    });
}

export async function scanSelectedFiles(options: {
    files: vscode.Uri[];
    scanEngine: ScanEngine;
    diagnostics: { applyFindings(doc: vscode.TextDocument, findings: any[]): void };
}): Promise<FolderScanSummary> {
    if (!options.files.length) {
        vscode.window.showInformationMessage('No supported source files were selected');
        return { status: 'empty', completed: 0, totalFindings: 0, errors: [], results: [] };
    }

    return scanUris({
        files: options.files,
        scanEngine: options.scanEngine,
        diagnostics: options.diagnostics,
        confirmLabel: 'Scan Selected Files',
        confirmMessage: `Owlvex: Scan ${options.files.length} selected file(s)?`,
        progressTitle: 'Owlvex: Scanning selected files',
        getShortName: (uri) => vscode.workspace.asRelativePath(uri, false) || path.basename(uri.fsPath),
    });
}

async function scanUris(options: {
    files: vscode.Uri[];
    scanEngine: ScanEngine;
    diagnostics: { applyFindings(doc: vscode.TextDocument, findings: any[]): void };
    confirmLabel: string;
    confirmMessage: string;
    progressTitle: string;
    getShortName: (uri: vscode.Uri) => string;
}): Promise<FolderScanSummary> {
    const files = options.files;

    const confirm = await vscode.window.showInformationMessage(
        options.confirmMessage,
        { modal: true },
        options.confirmLabel,
    );
    if (confirm !== options.confirmLabel) {
        return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
    }

    let completed = 0;
    let totalFindings = 0;
    const errors: string[] = [];
    const results: FolderScanFileResult[] = [];
    let cancelled = false;
    let cooldownUntil = 0;
    let consecutiveRateLimitHits = 0;
    let deterministicOnlyMode = false;

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: options.progressTitle,
            cancellable: true,
        },
        async (progress, token) => {
            for (const uri of files) {
                if (token.isCancellationRequested) {
                    cancelled = true;
                    break;
                }

                const remainingCooldownMs = cooldownUntil - Date.now();
                if (remainingCooldownMs > 0) {
                    progress.report({
                        message: `Provider rate limit hit. Cooling down for ${Math.ceil(remainingCooldownMs / 1000)}s before continuing...`,
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
                    const doc = await vscode.workspace.openTextDocument(uri);
                    const result = await options.scanEngine.scanDocument(doc, deterministicOnlyMode
                        ? {
                            forceDeterministicOnly: true,
                            deterministicOnlyReason: 'AI coverage intentionally paused for the rest of this repo scan after repeated provider 429 warnings. Owlvex returned deterministic-only results for this file.',
                        }
                        : undefined);
                    if ((result.warnings ?? []).some(warning => /\b429\b|rate limit/i.test(warning))) {
                        consecutiveRateLimitHits += 1;
                        const providerRetryAfterMs = extractRetryAfterMsFromWarnings(result.warnings);
                        const adaptiveCooldownMs = Math.min(
                            MAX_RATE_LIMIT_COOLDOWN_MS,
                            RATE_LIMIT_COOLDOWN_MS * (2 ** Math.max(0, consecutiveRateLimitHits - 1)),
                        );
                        cooldownUntil = Date.now() + Math.max(adaptiveCooldownMs, providerRetryAfterMs ?? 0);
                        if (consecutiveRateLimitHits >= AI_BUDGET_FALLBACK_THRESHOLD) {
                            deterministicOnlyMode = true;
                        }
                    } else {
                        consecutiveRateLimitHits = 0;
                        cooldownUntil = 0;
                    }
                    options.diagnostics.applyFindings(doc, result.findings);
                    totalFindings += result.findings.length;
                    results.push({ uri, result });
                    completed++;
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
