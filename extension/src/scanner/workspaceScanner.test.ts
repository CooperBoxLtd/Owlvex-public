import * as fs from 'fs/promises';
import * as vscode from 'vscode';
import { collectScannableFiles, getActiveScannableEditorUri, pickScanFiles, resolveScanFileTarget, scanFolder, scanSelectedFiles } from './workspaceScanner';

jest.mock('fs/promises');

const normalizeTestPath = (value: string) => value.replace(/\\/g, '/');

describe('workspaceScanner', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath ?? String(uri));
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
        expect(files.map(file => normalizeTestPath(file.fsPath))).toEqual(['d:/repo/src/app.js', 'd:/repo/src/util.ts']);
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

    it('returns failed status when every selected file errors', async () => {
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Selected Files');

        const scanEngine = {
            scanDocument: jest
                .fn()
                .mockRejectedValueOnce(new Error('provider timeout'))
                .mockRejectedValueOnce(new Error('provider timeout')),
        };

        const summary = await scanSelectedFiles({
            files: [vscode.Uri.file('d:\\repo\\src\\one.js'), vscode.Uri.file('d:\\repo\\src\\two.js')],
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(summary.status).toBe('failed');
        expect(summary.completed).toBe(0);
        expect(summary.errors).toEqual([
            'd:\\repo\\src\\one.js: provider timeout',
            'd:\\repo\\src\\two.js: provider timeout',
        ]);
    });

    it('supports multi-select file picking', async () => {
        const first = vscode.Uri.file('d:\\repo\\src\\a.js');
        const second = vscode.Uri.file('d:\\repo\\src\\b.js');
        (vscode.window.showOpenDialog as jest.Mock).mockResolvedValue([first, second]);

        const picked = await pickScanFiles();

        expect(vscode.window.showOpenDialog).toHaveBeenCalledWith(expect.objectContaining({
            canSelectFiles: true,
            canSelectMany: true,
            openLabel: 'Scan Selected Files',
        }));
        expect(picked).toEqual([first, second]);
    });

    it('uses the active supported editor for current-file scans before opening a picker', async () => {
        const activeUri = vscode.Uri.file('d:\\repo\\src\\active.js');
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: activeUri,
            },
        };

        const target = await resolveScanFileTarget();

        expect(target).toEqual(activeUri);
        expect(vscode.window.showOpenDialog).not.toHaveBeenCalled();
        expect(getActiveScannableEditorUri()).toEqual(activeUri);
    });

    it('falls back to the file picker when the active editor is unsupported', async () => {
        const pickedUri = vscode.Uri.file('d:\\repo\\src\\picked.js');
        (vscode.window.activeTextEditor as any) = {
            document: {
                uri: vscode.Uri.file('d:\\repo\\README.md'),
            },
        };
        (vscode.window.showOpenDialog as jest.Mock).mockResolvedValue([pickedUri]);

        const target = await resolveScanFileTarget();

        expect(target).toEqual(pickedUri);
        expect(vscode.window.showOpenDialog).toHaveBeenCalled();
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

    it('scans an explicit list of selected files', async () => {
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Selected Files');
        const scanEngine = {
            scanDocument: jest
                .fn()
                .mockResolvedValue({
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
                }),
        };

        const summary = await scanSelectedFiles({
            files: [vscode.Uri.file('d:\\repo\\src\\one.js'), vscode.Uri.file('d:\\repo\\src\\two.js')],
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(summary.status).toBe('completed');
        expect(summary.completed).toBe(2);
        expect(summary.totalFindings).toBe(2);
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'Owlvex: Scan 2 selected file(s)?',
            { modal: true },
            'Scan Selected Files',
        );
    });

    it('can skip redundant confirmation for explicit selected-files scans', async () => {
        const scanEngine = {
            scanDocument: jest
                .fn()
                .mockResolvedValue({
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
                }),
        };

        const summary = await scanSelectedFiles({
            files: [vscode.Uri.file('d:\\repo\\src\\one.js')],
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
            skipConfirmation: true,
        });

        expect(summary.status).toBe('completed');
        expect(vscode.window.showInformationMessage).not.toHaveBeenCalledWith(
            'Owlvex: Scan 1 selected file(s)?',
            { modal: true },
            'Scan Selected Files',
        );
    });

    it('keeps small selected-file Foundry scans interactive while still batching them', async () => {
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Selected Files');
        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation((section?: string) => ({
            get: (key: string, fallback?: any) => {
                if (section === 'owlvex' && key === 'provider') return 'azure-foundry';
                if (section === 'owlvex' && key === 'foundry.model') return 'owlvex-gpt54mini';
                return fallback;
            },
        }));

        const scanEngine = {
            scanDocumentsBatch: jest.fn().mockImplementation(async (documents: any[]) => documents.map((document: any, index: number) => ({
                scanId: `scan-${index + 1}`,
                score: 8,
                summary: `batched ${document.fileName}`,
                findings: [{ line: index + 1 }],
                positives: [],
                metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-gpt54mini',
                provider: 'azure-foundry',
                warnings: [],
            }))),
            scanDocument: jest.fn(),
        };

        const summary = await scanSelectedFiles({
            files: [vscode.Uri.file('d:\\repo\\src\\one.js'), vscode.Uri.file('d:\\repo\\src\\two.js')],
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(summary.status).toBe('completed');
        expect(scanEngine.scanDocumentsBatch).toHaveBeenCalledTimes(1);
        expect(scanEngine.scanDocument).not.toHaveBeenCalled();
        expect(vscode.window.showInformationMessage).not.toHaveBeenCalledWith(
            'Owlvex: Full AI scan will be paced to stay within provider quota. Estimated additional wait: about 30s.',
        );
        expect(setTimeoutSpy).not.toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
    });

    it('batches up to three files per AI pass and preserves result order', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'first.js', isDirectory: () => false, isFile: () => true },
                    { name: 'second.js', isDirectory: () => false, isFile: () => true },
                    { name: 'third.js', isDirectory: () => false, isFile: () => true },
                    { name: 'fourth.js', isDirectory: () => false, isFile: () => true },
                ];
            }
            return [];
        });
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Folder');
        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation((section?: string) => ({
            get: (key: string, fallback?: any) => {
                if (section === 'owlvex' && key === 'provider') return 'ollama';
                if (section === 'owlvex' && key === 'ollama.model') return 'qwen2.5:7b';
                return fallback;
            },
        }));

        const scanEngine = {
            scanDocumentsBatch: jest.fn().mockImplementation(async (documents: any[]) => documents.map((document: any, index: number) => ({
                scanId: `batch-scan-${index + 1}`,
                score: 8,
                summary: `batched ${document.fileName}`,
                findings: [{ line: index + 1 }],
                positives: [],
                metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-gpt54mini',
                provider: 'azure-foundry',
                warnings: [],
            }))),
            scanDocument: jest.fn().mockResolvedValue({
                scanId: 'scan-4',
                score: 7,
                summary: 'single fourth.js',
                findings: [{ line: 4 }],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 1, low: 0 },
                durationMs: 9,
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
        expect(scanEngine.scanDocumentsBatch).toHaveBeenCalledTimes(1);
        const batchFileNames = (scanEngine.scanDocumentsBatch as jest.Mock).mock.calls[0][0]
            .map((item: { fileName: string }) => normalizeTestPath(item.fileName));
        expect(batchFileNames).toEqual([
            'd:/repo/first.js',
            'd:/repo/second.js',
            'd:/repo/third.js',
        ]);
        expect(scanEngine.scanDocument).toHaveBeenCalledTimes(1);
        expect(normalizeTestPath((scanEngine.scanDocument as jest.Mock).mock.calls[0][0].fileName)).toBe('d:/repo/fourth.js');
        expect(summary.results.map(entry => normalizeTestPath(entry.uri.fsPath))).toEqual([
            'd:/repo/first.js',
            'd:/repo/second.js',
            'd:/repo/third.js',
            'd:/repo/fourth.js',
        ]);
        expect(diagnostics.applyFindings).toHaveBeenCalledTimes(4);
        setTimeoutSpy.mockRestore();
    });

    it('paces full Foundry review up front when the batch would otherwise outrun steady request budget', async () => {
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
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation((section?: string) => ({
            get: (key: string, fallback?: any) => {
                if (section === 'owlvex' && key === 'provider') return 'azure-foundry';
                if (section === 'owlvex' && key === 'foundry.model') return 'owlvex-gpt54mini';
                return fallback;
            },
        }));

        const scanEngine = {
            scanDocument: jest.fn().mockResolvedValue({
                scanId: 'scan-1',
                score: 8,
                summary: 'ok',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-gpt54mini',
                provider: 'azure-foundry',
                warnings: [],
            }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(1, expect.anything());
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(2, expect.anything());
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'Owlvex: Full AI scan will be paced to stay within provider quota. Estimated additional wait: about 60s.',
        );
        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
    });

    it('keeps large Foundry batches on full AI review instead of degrading them up front', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return Array.from({ length: 8 }, (_, index) => ({
                    name: `file-${index + 1}.js`,
                    isDirectory: () => false,
                    isFile: () => true,
                }));
            }
            return [];
        });
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Folder');
        const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
            fn();
            return 0 as any;
        }) as any);
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation((section?: string) => ({
            get: (key: string, fallback?: any) => {
                if (section === 'owlvex' && key === 'provider') return 'azure-foundry';
                if (section === 'owlvex' && key === 'foundry.model') return 'owlvex-gpt54mini';
                return fallback;
            },
        }));

        const scanEngine = {
            scanDocument: jest.fn().mockResolvedValue({
                scanId: 'scan-1',
                score: 8,
                summary: 'full-ai',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-gpt54mini',
                provider: 'azure-foundry',
                warnings: [],
            }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(1, expect.anything());
        expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
            'Owlvex: Full AI scan will be paced to stay within provider quota. Estimated additional wait: about 210s.',
        );
        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
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
                    model: 'test-foundry-deployment-secondary',
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
                    model: 'test-foundry-deployment-secondary',
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
                    model: 'test-foundry-deployment-secondary',
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
        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        expect(summary.results).toHaveLength(3);
        setTimeoutSpy.mockRestore();
    });

    it('uses adaptive cooldowns when provider rate limits repeat across files', async () => {
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
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: ['AI provider unavailable: Azure Foundry error: 429 retry-after: 7'],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-2',
                    score: 8,
                    summary: 'second',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: ['AI provider unavailable: Azure Foundry error: 429'],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-3',
                    score: 9,
                    summary: 'third',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 11,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: [],
                }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
    });

    it('keeps full-AI file scans even after repeated 429 warnings', async () => {
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
        jest.spyOn(global, 'setTimeout').mockImplementation(((fn: any) => {
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
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: ['AI provider unavailable: Azure Foundry error: 429'],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-2',
                    score: 8,
                    summary: 'second',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: ['AI provider unavailable: Azure Foundry error: 429'],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-3',
                    score: 7,
                    summary: 'third',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'test-foundry-deployment-secondary',
                    provider: 'azure-foundry',
                    warnings: [],
                }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(1, expect.anything());
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(2, expect.anything());
        expect(scanEngine.scanDocument).toHaveBeenNthCalledWith(3, expect.anything());
    });

    it('applies proactive request budgeting for Azure Foundry even before 429 warnings', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'first.js', isDirectory: () => false, isFile: () => true },
                    { name: 'second.js', isDirectory: () => false, isFile: () => true },
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
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'customer-foundry-deployment-a',
                    provider: 'azure-foundry',
                    warnings: [],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-2',
                    score: 9,
                    summary: 'second',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 11,
                    model: 'customer-foundry-deployment-a',
                    provider: 'azure-foundry',
                    warnings: [],
                }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
    });

    it('applies the same proactive request budgeting for another Azure Foundry deployment name', async () => {
        (fs.readdir as jest.Mock).mockImplementation(async (currentPath: string) => {
            if (currentPath.endsWith('repo')) {
                return [
                    { name: 'first.js', isDirectory: () => false, isFile: () => true },
                    { name: 'second.js', isDirectory: () => false, isFile: () => true },
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
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'customer-foundry-deployment-b',
                    provider: 'azure-foundry',
                    warnings: [],
                })
                .mockResolvedValueOnce({
                    scanId: 'scan-2',
                    score: 9,
                    summary: 'second',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 11,
                    model: 'customer-foundry-deployment-b',
                    provider: 'azure-foundry',
                    warnings: [],
                }),
        };

        await scanFolder({
            root: vscode.Uri.file('d:\\repo'),
            scanEngine: scanEngine as any,
            diagnostics: { applyFindings: jest.fn() },
        });

        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 30000);
        setTimeoutSpy.mockRestore();
    });
});
