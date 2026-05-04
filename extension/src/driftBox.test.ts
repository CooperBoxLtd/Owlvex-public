import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
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

    afterEach(() => {
        jest.restoreAllMocks();
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
        expect(parsed.checks[0].reason).toContain('configured Drift scripts folder');
    });

    it('accepts scripts from a configured Drift scripts folder', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'custom-script',
                label: 'Custom script',
                command: 'node check-auth-flow.mjs',
            },
        ]), {
            projectRoot,
            scriptsRoot: 'quality\\drift-scripts',
            scope: 'scan',
        });

        expect(parsed.warnings).toEqual([]);
        expect(parsed.readyChecks).toHaveLength(1);
        expect(parsed.readyChecks[0].scriptPath).toBe(path.resolve(projectRoot, 'quality\\drift-scripts\\check-auth-flow.mjs'));
        expect(parsed.readyChecks[0].command).toContain(path.resolve(projectRoot, 'quality\\drift-scripts\\check-auth-flow.mjs'));
    });

    it('accepts a package validation script when package.json defines it', () => {
        const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'owlvex-drift-'));
        fs.writeFileSync(path.join(tempRoot, 'package.json'), JSON.stringify({
            scripts: {
                validate: 'npm run build && npm run test',
            },
        }), 'utf8');

        const parsed = parseDriftBoxConfig(config([
            {
                id: 'app-validation',
                label: 'App validation',
                command: 'npm run validate',
                scope: ['scan', 'post-fix'],
            },
        ]), { projectRoot: tempRoot, scope: 'scan' });

        expect(parsed.warnings).toEqual([]);
        expect(parsed.readyChecks).toHaveLength(1);
        expect(parsed.readyChecks[0].commandKind).toBe('package-script');
        expect(parsed.readyChecks[0].command).toBe('npm run validate');
        expect(parsed.readyChecks[0].scriptPath).toBeUndefined();
    });

    it('rejects package validation scripts that are not defined in package.json', () => {
        const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'owlvex-drift-'));
        fs.writeFileSync(path.join(tempRoot, 'package.json'), JSON.stringify({ scripts: {} }), 'utf8');

        const parsed = parseDriftBoxConfig(config([
            {
                id: 'missing-validation',
                label: 'Missing validation',
                command: 'npm run validate',
            },
        ]), { projectRoot: tempRoot, scope: 'scan' });

        expect(parsed.readyChecks).toHaveLength(0);
        expect(parsed.checks[0].status).toBe('invalid');
        expect(parsed.checks[0].reason).toContain('scripts.validate');
    });

    it('filters checks by scope without treating frameworks as execution routing', () => {
        const parsed = parseDriftBoxConfig(config([
            {
                id: 'clean-code-contract',
                label: 'Clean Code contract',
                command: 'node .owlvex/drift/scripts/check-contract.mjs',
                frameworks: ['Clean Code'],
                scope: ['post-fix'],
            },
            {
                id: 'auth-behavior',
                label: 'Auth behavior',
                command: 'node .owlvex/drift/scripts/auth-behavior.mjs',
                frameworks: ['Clean Code'],
                scope: ['scan'],
            },
        ]), {
            projectRoot,
            selectedFrameworks: ['STRIDE'],
            scope: 'scan',
        });

        expect(parsed.readyChecks).toHaveLength(1);
        expect(parsed.checks[0].status).toBe('out_of_scope');
        expect(parsed.checks[1].status).toBe('ready');
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

    it('loads a configured Drift Box file and scripts folder', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') return projectRoot;
                if (key === 'driftBoxFile') return 'quality\\owlvex-drift.json';
                if (key === 'driftScriptsRoot') return 'quality\\scripts';
                return defaultValue;
            }),
        });
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from(config([
            {
                id: 'custom-contract',
                label: 'Custom contract',
                command: 'node check-contract.mjs',
            },
        ])));

        const loaded = await loadDriftBoxConfig({
            scope: 'scan',
            targetUris: [vscode.Uri.file(`${projectRoot}\\src\\server.js`)],
        });

        expect(loaded.found).toBe(true);
        expect(loaded.configPath).toBe('quality\\owlvex-drift.json');
        expect(loaded.readyChecks[0].scriptPath).toBe(path.resolve(projectRoot, 'quality\\scripts\\check-contract.mjs'));
        expect(vscode.workspace.fs.readFile).toHaveBeenCalledWith(expect.objectContaining({
            fsPath: path.join(projectRoot, 'quality', 'owlvex-drift.json'),
        }));
    });
});
