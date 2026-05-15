import * as fs from 'fs/promises';
import { execFile } from 'child_process';
import * as vscode from 'vscode';
import { collectChangedScannableFiles, collectChangedScannableFilesDetailed, collectGitTargetScannableFilesDetailed, collectScannableFiles, getActiveScannableEditorUri, pickScanFiles, resolveScanFileTarget, scanFolder, scanSelectedFiles } from './workspaceScanner';

jest.mock('fs/promises');
jest.mock('child_process', () => ({
    execFile: jest.fn(),
}));

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

    it('collects changed scannable files from git diff and untracked files', async () => {
        (execFile as unknown as jest.Mock)
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/changed.js\0README.md\0src/deleted.js\0package.json\0package-lock.json\0', ''))
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/new.ts\0src/changed.js\0scripts/electron-dev-launch.mjs\0', ''));
        (fs.stat as jest.Mock).mockImplementation(async (filePath: string) => {
            if (filePath.endsWith('deleted.js')) {
                throw new Error('missing');
            }
            return { isFile: () => true };
        });

        const files = await collectChangedScannableFiles(vscode.Uri.file('d:\\repo'));

        expect((execFile as unknown as jest.Mock).mock.calls[0][1]).toEqual([
            '-C',
            'd:\\repo',
            'diff',
            '--name-only',
            '-z',
            '--relative',
            '--diff-filter=ACMRTUXB',
            'HEAD',
            '--',
            '.',
        ]);
        expect(files.map(file => normalizeTestPath(file.fsPath))).toEqual([
            'd:/repo/src/changed.js',
            'd:/repo/package.json',
            'd:/repo/src/new.ts',
            'd:/repo/scripts/electron-dev-launch.mjs',
        ]);
    });

    it('reports changed files skipped because they are not source scan targets', async () => {
        (execFile as unknown as jest.Mock)
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/app.js\0APP_IMPROVEMENT_RECOMMENDATIONS.md\0.owlvex/drift/owlvex-drift.json\0package-lock.json\0.gitignore\0', ''))
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/new.ts\0', ''));
        (fs.stat as jest.Mock).mockResolvedValue({ isFile: () => true });

        const result = await collectChangedScannableFilesDetailed(vscode.Uri.file('d:\\repo'));

        expect(result.files.map(file => normalizeTestPath(file.fsPath))).toEqual([
            'd:/repo/src/app.js',
            'd:/repo/src/new.ts',
        ]);
        expect(result.gitChangedPaths).toEqual([
            'src/app.js',
            'APP_IMPROVEMENT_RECOMMENDATIONS.md',
            '.owlvex/drift/owlvex-drift.json',
            'package-lock.json',
            '.gitignore',
            'src/new.ts',
        ]);
        expect(result.skipped).toEqual([
            {
                path: 'APP_IMPROVEMENT_RECOMMENDATIONS.md',
                reason: 'documentation/context file; use TDD Box or Design Box when it should ground a scan',
            },
            {
                path: '.owlvex/drift/owlvex-drift.json',
                reason: 'configuration file; not currently scanned as source',
            },
            {
                path: 'package-lock.json',
                reason: 'lockfile; dependency/supply-chain scanning is separate from source scanning',
            },
            {
                path: '.gitignore',
                reason: 'Git metadata; not scanned as application source',
            },
        ]);
    });

    it('collects scannable files from a specific Git commit', async () => {
        (execFile as unknown as jest.Mock)
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/route.js\0README.md\0package.json\0', ''));
        (fs.stat as jest.Mock).mockResolvedValue({ isFile: () => true });

        const result = await collectGitTargetScannableFilesDetailed(vscode.Uri.file('d:\\repo'), 'abc123');

        expect((execFile as unknown as jest.Mock).mock.calls[0][1]).toEqual([
            '-C',
            'd:\\repo',
            'diff-tree',
            '--root',
            '--no-commit-id',
            '--name-only',
            '-r',
            '-z',
            '--diff-filter=ACMRTUXB',
            'abc123',
            '--',
            '.',
        ]);
        expect(result.files.map(file => normalizeTestPath(file.fsPath))).toEqual([
            'd:/repo/src/route.js',
            'd:/repo/package.json',
        ]);
        expect(result.skipped).toEqual([{
            path: 'README.md',
            reason: 'documentation/context file; use TDD Box or Design Box when it should ground a scan',
        }]);
        expect(result.errors).toEqual([]);
    });

    it('collects scannable files from a Git range', async () => {
        (execFile as unknown as jest.Mock)
            .mockImplementationOnce((_command: string, _args: string[], _options: any, callback: any) => callback(null, 'src/a.ts\0src/b.ts\0', ''));
        (fs.stat as jest.Mock).mockResolvedValue({ isFile: () => true });

        const result = await collectGitTargetScannableFilesDetailed(vscode.Uri.file('d:\\repo'), 'main..feature/login');

        expect((execFile as unknown as jest.Mock).mock.calls[0][1]).toEqual([
            '-C',
            'd:\\repo',
            'diff',
            '--name-only',
            '-z',
            '--relative',
            '--diff-filter=ACMRTUXB',
            'main..feature/login',
            '--',
            '.',
        ]);
        expect(result.files.map(file => normalizeTestPath(file.fsPath))).toEqual([
            'd:/repo/src/a.ts',
            'd:/repo/src/b.ts',
        ]);
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

    it('prepares Drift Box once for a multi-file scan and reuses it for each batch', async () => {
        const files = [
            vscode.Uri.file('d:\\repo\\src\\one.js'),
            vscode.Uri.file('d:\\repo\\src\\two.js'),
            vscode.Uri.file('d:\\repo\\src\\three.js'),
            vscode.Uri.file('d:\\repo\\src\\four.js'),
        ];
        const sharedDrift = {
            driftBoxContext: {
                found: true,
                summary: 'drift box 1 ready',
                warnings: [],
                checks: [],
            },
            driftResults: [{
                id: 'validate',
                label: 'validate',
                command: 'npm run validate',
                status: 'passed',
                exitCode: 0,
                durationMs: 100,
                stdout: 'ok',
                stderr: '',
            }],
        };
        const scanEngine = {
            prepareSharedDriftScanContext: jest.fn().mockResolvedValue(sharedDrift),
            scanDocumentsBatch: jest.fn(async (documents: any[], options: any) => documents.map((document: any) => ({
                scanId: `scan-${document.fileName}`,
                score: 0,
                summary: 'clean',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-test-model',
                provider: 'test-provider',
                warnings: [],
                driftBox: options.sharedDrift.driftBoxContext,
                driftResults: options.sharedDrift.driftResults,
            }))),
            scanDocument: jest.fn(async (document: any, options: any) => ({
                scanId: `scan-${document.fileName}`,
                score: 0,
                summary: 'clean',
                findings: [],
                positives: [],
                metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                durationMs: 10,
                model: 'owlvex-test-model',
                provider: 'test-provider',
                warnings: [],
                driftBox: options.driftBoxContext,
                driftResults: options.driftResults,
            })),
        };
        const diagnostics = { applyFindings: jest.fn() };

        const summary = await scanSelectedFiles({
            files,
            scanEngine: scanEngine as any,
            diagnostics,
            skipConfirmation: true,
        });

        expect(scanEngine.prepareSharedDriftScanContext).toHaveBeenCalledTimes(1);
        expect(scanEngine.prepareSharedDriftScanContext).toHaveBeenCalledWith(files, 'scan');
        expect(scanEngine.scanDocumentsBatch).toHaveBeenCalledTimes(1);
        expect(scanEngine.scanDocument).toHaveBeenCalledTimes(1);
        expect(scanEngine.scanDocumentsBatch.mock.calls[0][1]).toEqual({ sharedDrift });
        expect(scanEngine.scanDocument.mock.calls[0][1]).toEqual({
            driftBoxContext: sharedDrift.driftBoxContext,
            driftResults: sharedDrift.driftResults,
        });
        expect(summary.results).toHaveLength(4);
        expect(summary.results.every(item => item.result.driftResults === sharedDrift.driftResults)).toBe(true);
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

    it('retries clean deterministic-only batch results with a single-file AI scan', async () => {
        (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue('Scan Selected Files');
        (vscode.workspace.getConfiguration as jest.Mock).mockImplementation((section?: string) => ({
            get: (key: string, fallback?: any) => {
                if (section === 'owlvex' && key === 'provider') return 'openai';
                if (section === 'owlvex' && key === 'openai.model') return 'gpt-4o';
                return fallback;
            },
        }));

        const scanEngine = {
            scanDocumentsBatch: jest.fn().mockResolvedValue([
                {
                    scanId: 'batch-clean-static-only',
                    score: 0,
                    summary: 'No deterministic findings.',
                    findings: [],
                    positives: [],
                    metrics: { critical: 0, high: 0, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'gpt-4o (deterministic-only)',
                    provider: 'openai',
                    warnings: ['AI provider unavailable in batch scan.'],
                },
                {
                    scanId: 'batch-ai-second',
                    score: 8,
                    summary: 'batched second',
                    findings: [{ line: 2 }],
                    positives: [],
                    metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                    durationMs: 10,
                    model: 'gpt-4o',
                    provider: 'openai',
                    warnings: [],
                },
            ]),
            scanDocument: jest.fn().mockResolvedValue({
                scanId: 'retry-ai-first',
                score: 9,
                summary: 'single-file retry found issue',
                findings: [{ line: 1 }],
                positives: [],
                metrics: { critical: 0, high: 1, medium: 0, low: 0 },
                durationMs: 12,
                model: 'gpt-4o',
                provider: 'openai',
                warnings: [],
            }),
        };
        const diagnostics = { applyFindings: jest.fn() };

        const summary = await scanSelectedFiles({
            files: [vscode.Uri.file('d:\\repo\\src\\one.js'), vscode.Uri.file('d:\\repo\\src\\two.js')],
            scanEngine: scanEngine as any,
            diagnostics,
        });

        expect(summary.status).toBe('completed');
        expect(scanEngine.scanDocumentsBatch).toHaveBeenCalledTimes(1);
        expect(scanEngine.scanDocument).toHaveBeenCalledTimes(1);
        expect(normalizeTestPath((scanEngine.scanDocument as jest.Mock).mock.calls[0][0].fileName)).toBe('d:/repo/src/one.js');
        expect(summary.results[0].result.scanId).toBe('retry-ai-first');
        expect(summary.results[0].result.warnings).toContain('Batch AI retry: single-file AI scan replaced a clean deterministic-only batch result.');
        expect(summary.totalFindings).toBe(2);
        expect(diagnostics.applyFindings).toHaveBeenNthCalledWith(1, expect.anything(), [{ line: 1 }]);
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
