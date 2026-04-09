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
    status: 'completed' | 'cancelled' | 'empty';
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

    const confirm = await vscode.window.showInformationMessage(
        `Owlvex: Scan ${files.length} file(s) in ${path.basename(options.root.fsPath)}?`,
        { modal: true },
        'Scan Folder',
    );
    if (confirm !== 'Scan Folder') {
        return { status: 'cancelled', completed: 0, totalFindings: 0, errors: [], results: [] };
    }

    let completed = 0;
    let totalFindings = 0;
    const errors: string[] = [];
    const results: FolderScanFileResult[] = [];
    let cancelled = false;

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Owlvex: Scanning ${path.basename(options.root.fsPath)}`,
            cancellable: true,
        },
        async (progress, token) => {
            for (const uri of files) {
                if (token.isCancellationRequested) {
                    cancelled = true;
                    break;
                }

                const attemptedIndex = completed + errors.length + 1;
                const shortName = path.relative(options.root.fsPath, uri.fsPath) || path.basename(uri.fsPath);
                progress.report({
                    message: `${shortName} (${attemptedIndex}/${files.length})`,
                    increment: (1 / files.length) * 100,
                });

                try {
                    const doc = await vscode.workspace.openTextDocument(uri);
                    const result = await options.scanEngine.scanDocument(doc);
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
        status: cancelled ? 'cancelled' : 'completed',
        completed,
        totalFindings,
        errors,
        results,
    };
}
