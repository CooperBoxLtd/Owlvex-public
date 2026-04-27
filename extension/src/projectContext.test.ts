import * as vscode from 'vscode';
import { getProjectRootSummaryFromConfig, loadProjectContextInfo, resolveProjectRootInfo } from './projectContext';

describe('project root helpers', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.workspaceFolders as any).length = 0;
        (vscode.workspace.fs.stat as jest.Mock).mockResolvedValue({ type: vscode.FileType.Directory });
        (vscode.workspace.fs.readFile as jest.Mock).mockReset();
    });

    it('uses the configured project root summary when one is stored', () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => key === 'projectRoot' ? 'D:\\repo\\service' : defaultValue),
        });

        expect(getProjectRootSummaryFromConfig()).toBe('D:\\repo\\service');
    });

    it('falls back to the first workspace folder when no project root is configured', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((_: string, defaultValue?: any) => defaultValue),
        });
        (vscode.workspace.workspaceFolders as any).push({
            name: 'service',
            uri: { fsPath: 'D:\\repo\\service', scheme: 'file', toString: () => 'D:\\repo\\service' },
        });

        const root = await resolveProjectRootInfo();
        expect(root.summary).toBe('default workspace (service)');
        expect(root.isConfigured).toBe(false);
    });

    it('skips configured project context when the scan target is outside that root', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext') {
                    return 'Benchmark app only context.';
                }
                if (key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath);

        const context = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\demo\\74-go-jwt-validation-unsafe.go')],
        });

        expect(context.summary).toBe('configured project root skipped for out-of-root target');
        expect(context.combined).toContain('Project context skipped');
        expect(context.combined).toContain('outside the configured project root');
        expect(context.combined).not.toContain('Benchmark app only context.');
    });

    it('keeps configured project context when the scan target is inside that root', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext') {
                    return 'Benchmark app only context.';
                }
                if (key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath);

        const context = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.summary).toContain('project root D:\\repo\\tools\\benchmark-app');
        expect(context.summary).toContain('inline project contract');
        expect(context.combined).toContain('Benchmark app only context.');
    });
});
