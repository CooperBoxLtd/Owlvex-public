import * as fs from 'fs/promises';
import * as vscode from 'vscode';
import { collectScannableFiles, scanFolder } from './workspaceScanner';

jest.mock('fs/promises');

describe('workspaceScanner', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.openTextDocument as jest.Mock).mockImplementation(async (uri: any) => ({
            uri,
            fileName: uri.fsPath,
            languageId: 'javascript',
            getText: () => 'const x = 1;',
        }));
        (vscode.window.withProgress as jest.Mock).mockImplementation(async (_options: any, task: any) => {
            const progress = { report: jest.fn() };
            const token = { isCancellationRequested: false };
            return task(progress, token);
        });
    });

    it('collects supported files and skips excluded directories', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'src', isDirectory: () => true, isFile: () => false },
                    { name: 'node_modules', isDirectory: () => true, isFile: () => false },
                    { name: 'README.md', isDirectory: () => false, isFile: () => true },
                ];
            }
            if (currentPath.endsWith('src')) {
                return [
                    { name: 'app.js', isDirectory: () => false, isFile: () => true },
                    { name: 'util.ts', isDirectory: () => false, isFile: () => true },
                ];
            }
            return [];
        });

        const files = await collectScannableFiles(vscode.Uri.file('d:\\repo'));
        expect(files.map(file => file.fsPath)).toEqual(['d:\\repo\\src\\app.js', 'd:\\repo\\src\\util.ts']);
    });

    it('counts only successful scans as completed', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'good.js', isDirectory: () => false, isFile: () => true },
                    { name: 'bad.js', isDirectory: () => false, isFile: () => true },
                ];
            }
            return [];
        });
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Folder');

        const scanEngine = {
            scanDocument: jest
                .fn()
                .mockResolvedValueOnce({
                    scanId: 'scan-1',
                    score: 8,
                    summary: 'ok',
                    findings: [{ line: 1 }],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 1 },
                    durationMs: 10,
                    model: 'qwen2.5:7b',
                    provider: 'ollama',
                    warnings: [],
                })
                .mockRejectedValueOnce(new Error('provider timeout')),
        };
        const diagnostics = { applyFindings: jest.fn() };

        const summary = await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics,
        });

        expect(summary.status).toBe('completed');
        expect(summary.completed).toBe(1);
        expect(summary.errors).toEqual(['bad.js: provider timeout']);
        expect(summary.results).toHaveLength(1);
        expect(summary.totalFindings).toBe(1);
    });

    it('returns empty status when no supported files are found', async () => {
        (fs.readdir as jest.Mock).mockResolvedValue([]);

        const summary = await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: { scanDocument: jest.fn() } as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(summary.status).toBe('empty');
        expect(summary.completed).toBe(0);
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'No supported source files found in the selected folder'
        );
    });

    it('returns cancelled status when the user declines the folder scan', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'good.js', isDirectory: () => false, isFile: () => true },
                ];
            }
            return [];
        });
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue(undefined);

        const summary = await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: { scanDocument: jest.fn() } as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(summary.status).toBe('cancelled');
        expect(summary.completed).toBe(0);
    });

    it('waits before scanning the next file after a provider rate limit warning', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'first.js', isDirectory: () => false, isFile: () => true },
                    { name: 'second.js', isDirectory: () => false, isFile: () => true },
                    { name: 'third.js', isDirectory: () => false, isFile: () => true },
                ];
            }
            return [];
        });
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Folder');
        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);

        const scanEngine = {
            scanDocument: jest
                .fn()
                .mockResolvedValueOnce({
                    scanId: 'scan-1',
                    score: 8,
                    summary: 'first',
                    findings: [{ line: 1 }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'owlvex-gpt54mini',
                    provider: 'azure-foundry',
                    warnings: ['AI provider unavailable: Azure Foundry error: 429'],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-2',
                    score: 7,
                    summary: 'second',
                    findings: [{ line: 2 }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    durationMs: 12,
                    model: 'owlvex-gpt54mini',
                    provider: 'azure-foundry',
                    warnings: [],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-3',
                    score: 9,
                    summary: 'third',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 11,
                    model: 'owlvex-gpt54mini',
                    provider: 'azure-foundry',
                    warnings: [],
                }),
        };
        const diagnostics = { applyFindings: jest.fn() };

        const summary = await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics,
        });

        expect(summary.status).toBe('completed');
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(1, expect.anything());
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(2, expect.anything());
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(3, expect.anything());
        expect(setTimeoutSpy).toHaveBeenCalled();
        expect(summary.results).toHaveLength(3);
        setTimeoutSpy.mockRestore();
    });
});
