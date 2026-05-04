import { EventEmitter } from 'events';
import * as vscode from 'vscode';
import { DriftApprovalStorage, runDriftChecks } from './driftRunner';
import type { DriftBoxLoadResult } from './driftBox';

jest.mock('child_process', () => ({
    spawn: jest.fn(),
}));

const { spawn } = jest.requireMock('child_process') as { spawn: jest.Mock };
const projectRoot = 'D:\\repo\\tools\\benchmark-app';

function buildDriftBox(overrides: Partial<DriftBoxLoadResult> = {}): DriftBoxLoadResult {
    const check = {
        id: 'api-contract',
        label: 'API contract',
        command: 'node .owlvex/drift/scripts/api-contract.mjs',
        frameworks: ['STRIDE'],
        scope: ['scan' as const],
        timeoutSeconds: 30,
        enabled: true,
        scriptPath: `${projectRoot}\\.owlvex\\drift\\scripts\\api-contract.mjs`,
        status: 'ready' as const,
        warnings: [],
    };

    return {
        found: true,
        configPath: '.owlvex\\drift\\owlvex-drift.json',
        version: 1,
        checks: [check],
        readyChecks: [check],
        warnings: [],
        summary: 'drift box 1 ready',
        ...overrides,
    };
}

function mockChildProcess(exitCode = 0, stdout = 'ok', stderr = '') {
    const child = new EventEmitter() as EventEmitter & {
        stdout: EventEmitter;
        stderr: EventEmitter;
        kill: jest.Mock;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = jest.fn();
    spawn.mockReturnValue(child);
    setImmediate(() => {
        if (stdout) child.stdout.emit('data', Buffer.from(stdout));
        if (stderr) child.stderr.emit('data', Buffer.from(stderr));
        child.emit('close', exitCode);
    });
    return child;
}

function mockStorage(approved: boolean, update = jest.fn().mockResolvedValue(undefined)): DriftApprovalStorage {
    return {
        get: jest.fn(<T,>(_key: string, defaultValue?: T) => approved as T ?? defaultValue),
        update,
    };
}

describe('drift runner', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.useRealTimers();
        (vscode.window.showWarningMessage as jest.Mock).mockResolvedValue('Run Drift Checks');
    });

    it('requires approval before running ready checks and persists that approval', async () => {
        const update = jest.fn().mockResolvedValue(undefined);
        const storage = mockStorage(false, update);
        mockChildProcess(0, 'contract ok');

        const results = await runDriftChecks(buildDriftBox(), {
            projectRoot,
            storage,
        });

        expect(vscode.window.showWarningMessage).toHaveBeenCalledWith(
            expect.stringContaining('wants to run 1 local check'),
            { modal: true },
            'Run Drift Checks',
            'Cancel',
        );
        expect(update).toHaveBeenCalledWith(expect.stringContaining('owlvex.drift.approval.'), true);
        expect(spawn).toHaveBeenCalledWith('node', ['.owlvex/drift/scripts/api-contract.mjs'], {
            cwd: projectRoot,
            shell: false,
            windowsHide: true,
        });
        expect(results[0]).toMatchObject({
            id: 'api-contract',
            status: 'passed',
            exitCode: 0,
            stdout: 'contract ok',
        });
    });

    it('returns not approved results when the user cancels', async () => {
        (vscode.window.showWarningMessage as jest.Mock).mockResolvedValue('Cancel');

        const results = await runDriftChecks(buildDriftBox(), {
            projectRoot,
            storage: mockStorage(false),
        });

        expect(spawn).not.toHaveBeenCalled();
        expect(results[0].status).toBe('not_approved');
        expect(results[0].reason).toContain('not approve');
    });

    it('does not prompt again when approval is already stored', async () => {
        mockChildProcess(0);

        await runDriftChecks(buildDriftBox(), {
            projectRoot,
            storage: mockStorage(true),
        });

        expect(vscode.window.showWarningMessage).not.toHaveBeenCalled();
        expect(spawn).toHaveBeenCalledTimes(1);
    });

    it('reports failed checks with captured stderr', async () => {
        mockChildProcess(2, '', 'contract failed');

        const results = await runDriftChecks(buildDriftBox(), {
            projectRoot,
            requireApproval: false,
        });

        expect(results[0]).toMatchObject({
            status: 'failed',
            exitCode: 2,
            stderr: 'contract failed',
        });
    });

    it('runs approved package validation scripts', async () => {
        const driftBox = buildDriftBox();
        driftBox.readyChecks[0] = {
            ...driftBox.readyChecks[0],
            id: 'app-validation',
            label: 'App validation',
            command: 'npm run validate',
            commandKind: 'package-script',
            scriptPath: undefined,
        };
        mockChildProcess(0, 'validation ok');

        const results = await runDriftChecks(driftBox, {
            projectRoot,
            requireApproval: false,
        });

        const expectedExecutable = process.platform === 'win32' ? 'cmd.exe' : 'npm';
        const expectedArgs = process.platform === 'win32' ? ['/d', '/s', '/c', 'npm run validate'] : ['run', 'validate'];
        expect(spawn).toHaveBeenCalledWith(expectedExecutable, expectedArgs, {
            cwd: projectRoot,
            shell: false,
            windowsHide: true,
        });
        expect(results[0]).toMatchObject({
            id: 'app-validation',
            status: 'passed',
            stdout: 'validation ok',
        });
    });

    it('skips ready checks if the validated script path is missing or unsafe', async () => {
        const driftBox = buildDriftBox();
        driftBox.readyChecks[0] = {
            ...driftBox.readyChecks[0],
            scriptPath: 'D:\\repo\\outside.mjs',
        };

        const results = await runDriftChecks(driftBox, {
            projectRoot,
            requireApproval: false,
        });

        expect(spawn).not.toHaveBeenCalled();
        expect(results[0].status).toBe('skipped');
        expect(results[0].reason).toContain('outside .owlvex/drift/scripts');
    });

    it('returns no results when no ready checks exist', async () => {
        const results = await runDriftChecks(buildDriftBox({
            checks: [],
            readyChecks: [],
            found: true,
        }), {
            projectRoot,
        });

        expect(results).toEqual([]);
        expect(spawn).not.toHaveBeenCalled();
    });
});
