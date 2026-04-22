import * as vscode from 'vscode';
import { getProjectRootSummaryFromConfig, resolveProjectRootInfo } from './projectContext';

describe('project root helpers', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.workspaceFolders as any).length = 0;
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
});
