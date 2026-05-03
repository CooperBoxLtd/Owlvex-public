import * as path from 'path';
import * as vscode from 'vscode';
import { loadDriftBoxConfig, parseDriftBoxConfig } from './driftBox';

const projectRoot = 'D:\\repo\\tools\\benchmark-app';

function config(checks: unknown[]): string {
    return JSON.stringify({ version: 1, checks });
}

describe('drift box config parser', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.workspaceFolders as any).length = 0;
        (vscode.workspace.fs.stat as jest.Mock).mockResolvedValue({ type: vscode.FileType.Directory });
        (vscode.workspace.fs.readFile as jest.Mock).mockReset();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath);
    });

    it('accepts a safe script command inside the Drift Box scripts directory', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'auth-flow',
                label: 'Authentication flow still works',
                command: 'node .owlvex/drift/scripts/check-auth-flow.mjs',
                frameworks: ['STRIDE', 'OWASP'],
                scope: ['scan', 'post-fix'],
                timeoutSeconds: 45,
            },
        ]), {
            projectRoot,
            selectedFrameworks: ['STRIDE'],
            scope: 'scan',
        });

        expect(parsed.warnings).toEqual([]);
        expect(parsed.readyChecks).toHaveLength(1);
        expect(parsed.readyChecks[0].scriptPath).toBe(path.resolve(projectRoot, '.owlvex/drift/scripts/check-auth-flow.mjs'));
        expect(parsed.summary).toContain('1 ready');
    });

    it('marks checks with shell chaining or redirects as invalid', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'bad-command',
                label: 'Bad command',
                command: 'node .owlvex/drift/scripts/check.mjs && npm test',
            },
        ]), { projectRoot, scope: 'scan' });

        expect(parsed.readyChecks).toHaveLength(0);
        expect(parsed.checks[0].status).toBe('invalid');
        expect(parsed.checks[0].reason).toContain('shell chaining');
        expect(parsed.warnings[0]).toContain('bad-command');
    });

    it('requires commands to reference scripts under .owlvex/drift/scripts', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'outside-script',
                label: 'Outside script',
                command: 'node scripts/check-auth-flow.mjs',
            },
        ]), { projectRoot, scope: 'scan' });

        expect(parsed.checks[0].status).toBe('invalid');
        expect(parsed.checks[0].reason).toContain('.owlvex/drift/scripts');
    });

    it('filters checks by scope and selected frameworks without making them invalid', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'clean-code-contract',
                label: 'Clean Code contract',
                command: 'node .owlvex/drift/scripts/check-contract.mjs',
                frameworks: ['Clean Code'],
                scope: ['post-fix'],
            },
        ]), {
            projectRoot,
            selectedFrameworks: ['STRIDE'],
            scope: 'scan',
        });

        expect(parsed.readyChecks).toHaveLength(0);
        expect(parsed.checks[0].status).toBe('out_of_scope');
    });

    it('defaults timeout, scope, and enabled state conservatively', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'defaults',
                label: 'Defaults',
                command: 'node .owlvex/drift/scripts/defaults.mjs',
            },
            {
                id: 'disabled',
                label: 'Disabled',
                enabled: false,
                command: 'node .owlvex/drift/scripts/disabled.mjs',
            },
        ]), { projectRoot });

        expect(parsed.checks[0].timeoutSeconds).toBe(30);
        expect(parsed.checks[0].scope).toEqual(['scan']);
        expect(parsed.checks[0].enabled).toBe(true);
        expect(parsed.checks[0].status).toBe('ready');
        expect(parsed.checks[1].status).toBe('disabled');
    });
});

describe('drift box config loader', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.workspaceFolders as any).length = 0;
        (vscode.workspace.fs.stat as jest.Mock).mockResolvedValue({ type: vscode.FileType.Directory });
        (vscode.workspace.fs.readFile as jest.Mock).mockReset();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace(`${projectRoot}\\`, ''));
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => key === 'projectRoot' ? projectRoot : defaultValue),
        });
    });

    it('loads the selected project root drift config', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from(config([
            {
                id: 'api-contract',
                label: 'API contract',
                command: 'node .owlvex/drift/scripts/api-contract.mjs',
            },
        ])));

        const loaded = await loadDriftBoxConfig({
            scope: 'scan',
            targetUris: [vscode.Uri.file(`${projectRoot}\\src\\server.js`)],
        });

        expect(loaded.found).toBe(true);
        expect(loaded.configPath).toBe('.owlvex\\drift\\owlvex-drift.json');
        expect(loaded.readyChecks).toHaveLength(1);
        expect(vscode.workspace.fs.readFile).toHaveBeenCalledWith(expect.objectContaining({
            fsPath: path.join(projectRoot, '.owlvex', 'drift', 'owlvex-drift.json'),
        }));
    });

    it('skips drift config for out-of-root targets', async () => {
        const loaded = await loadDriftBoxConfig({
            targetUris: [vscode.Uri.file('D:\\repo\\other\\src\\server.js')],
        });

        expect(loaded.found).toBe(false);
        expect(loaded.summary).toBe('drift box skipped for out-of-root target');
        expect(vscode.workspace.fs.readFile).not.toHaveBeenCalled();
    });

    it('returns not found when the drift config does not exist', async () => {
        (vscode.workspace.fs.readFile as jest.Mock).mockRejectedValue(new Error('missing'));

        const loaded = await loadDriftBoxConfig({
            targetUris: [vscode.Uri.file(`${projectRoot}\\src\\server.js`)],
        });

        expect(loaded.found).toBe(false);
        expect(loaded.summary).toBe('no drift box');
        expect(loaded.readyChecks).toHaveLength(0);
    });
});
