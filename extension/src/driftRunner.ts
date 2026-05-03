import { spawn } from 'child_process';
import { createHash } from 'crypto';
import * as path from 'path';
import * as vscode from 'vscode';
import type { DriftBoxLoadResult, DriftCheckDefinition } from './driftBox';

export type DriftRunStatus = 'passed' | 'failed' | 'skipped' | 'timed_out' | 'not_approved';

export interface DriftRunResult {
    id: string;
    label: string;
    command: string;
    status: DriftRunStatus;
    exitCode?: number | null;
    durationMs: number;
    stdout: string;
    stderr: string;
    reason?: string;
}

export interface DriftApprovalStorage {
    get<T>(key: string, defaultValue?: T): T | undefined;
    update(key: string, value: unknown): Thenable<void> | Promise<void>;
}

export interface RunDriftChecksOptions {
    projectRoot: string;
    storage?: DriftApprovalStorage;
    requireApproval?: boolean;
    approvalKeySalt?: string;
    outputLimitBytes?: number;
}

const APPROVAL_STORAGE_PREFIX = 'owlvex.drift.approval';
const DEFAULT_OUTPUT_LIMIT_BYTES = 8000;
const PROCESS_KILL_GRACE_MS = 250;
const DISALLOWED_COMMAND_TOKENS = /(\|\||&&|[|;`<>])/;

function unquote(value: string): string {
    const trimmed = value.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}

function splitCommand(command: string): string[] {
    return command.match(/"[^"]+"|'[^']+'|\S+/g)?.map(unquote) ?? [];
}

function isInside(parentPath: string, candidatePath: string): boolean {
    const parent = path.resolve(parentPath).toLowerCase();
    const candidate = path.resolve(candidatePath).toLowerCase();
    return candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
}

function appendCapped(current: string, chunk: Buffer | string, limitBytes: number): string {
    const next = current + chunk.toString();
    if (Buffer.byteLength(next, 'utf8') <= limitBytes) {
        return next;
    }

    return Buffer.from(next, 'utf8').subarray(0, limitBytes).toString('utf8') + '\n[truncated]';
}

function buildApprovalKey(driftBox: DriftBoxLoadResult, options: RunDriftChecksOptions): string {
    const hash = createHash('sha256')
        .update(options.projectRoot)
        .update(options.approvalKeySalt ?? '')
        .update(driftBox.configPath ?? '')
        .update(JSON.stringify(driftBox.readyChecks.map(check => ({
            id: check.id,
            command: check.command,
            scriptPath: check.scriptPath,
        }))))
        .digest('hex');
    return `${APPROVAL_STORAGE_PREFIX}.${hash}`;
}

function buildNotApprovedResults(checks: DriftCheckDefinition[], reason: string): DriftRunResult[] {
    return checks.map(check => ({
        id: check.id,
        label: check.label,
        command: check.command,
        status: 'not_approved',
        durationMs: 0,
        stdout: '',
        stderr: '',
        reason,
    }));
}

async function ensureApproval(driftBox: DriftBoxLoadResult, options: RunDriftChecksOptions): Promise<{ approved: boolean; reason?: string }> {
    if (options.requireApproval === false || !driftBox.readyChecks.length) {
        return { approved: true };
    }

    const storage = options.storage;
    const approvalKey = storage ? buildApprovalKey(driftBox, options) : '';
    if (storage?.get<boolean>(approvalKey, false)) {
        return { approved: true };
    }

    const configLabel = driftBox.configPath ? ` from ${driftBox.configPath}` : '';
    const choice = await vscode.window.showWarningMessage(
        `Owlvex Drift Box wants to run ${driftBox.readyChecks.length} local check(s)${configLabel}. Review the repository-owned scripts before approving.`,
        { modal: true },
        'Run Drift Checks',
        'Cancel',
    );

    if (choice !== 'Run Drift Checks') {
        return { approved: false, reason: 'User did not approve Drift Box execution.' };
    }

    if (storage && approvalKey) {
        await storage.update(approvalKey, true);
    }
    return { approved: true };
}

function validateRunnableCheck(check: DriftCheckDefinition, projectRoot: string): string | undefined {
    if (check.status !== 'ready') {
        return `Check is ${check.status}.`;
    }
    if (!check.scriptPath) {
        return 'Validated script path is missing.';
    }
    if (!isInside(path.join(projectRoot, '.owlvex', 'drift', 'scripts'), check.scriptPath)) {
        return 'Validated script path is outside .owlvex/drift/scripts.';
    }
    if (DISALLOWED_COMMAND_TOKENS.test(check.command)) {
        return 'Command contains shell chaining, pipes, redirects, or backticks.';
    }
    const parts = splitCommand(check.command);
    if (!parts.length) {
        return 'Command is empty.';
    }
    return undefined;
}

async function runOneCheck(check: DriftCheckDefinition, options: RunDriftChecksOptions): Promise<DriftRunResult> {
    const invalidReason = validateRunnableCheck(check, options.projectRoot);
    if (invalidReason) {
        return {
            id: check.id,
            label: check.label,
            command: check.command,
            status: 'skipped',
            durationMs: 0,
            stdout: '',
            stderr: '',
            reason: invalidReason,
        };
    }

    const commandParts = splitCommand(check.command);
    const executable = commandParts[0];
    const args = commandParts.slice(1);
    const outputLimitBytes = options.outputLimitBytes ?? DEFAULT_OUTPUT_LIMIT_BYTES;
    const startedAt = Date.now();

    return new Promise(resolve => {
        let stdout = '';
        let stderr = '';
        let settled = false;
        const child = spawn(executable, args, {
            cwd: options.projectRoot,
            shell: false,
            windowsHide: true,
        });

        const finish = (status: DriftRunStatus, exitCode: number | null | undefined, reason?: string) => {
            if (settled) {
                return;
            }
            settled = true;
            resolve({
                id: check.id,
                label: check.label,
                command: check.command,
                status,
                exitCode,
                durationMs: Date.now() - startedAt,
                stdout,
                stderr,
                reason,
            });
        };

        const timeout = setTimeout(() => {
            child.kill();
            setTimeout(() => finish('timed_out', null, `Timed out after ${check.timeoutSeconds}s.`), PROCESS_KILL_GRACE_MS);
        }, check.timeoutSeconds * 1000);

        child.stdout?.on('data', chunk => {
            stdout = appendCapped(stdout, chunk, outputLimitBytes);
        });
        child.stderr?.on('data', chunk => {
            stderr = appendCapped(stderr, chunk, outputLimitBytes);
        });
        child.on('error', error => {
            clearTimeout(timeout);
            finish('failed', null, error.message);
        });
        child.on('close', code => {
            clearTimeout(timeout);
            finish(code === 0 ? 'passed' : 'failed', code);
        });
    });
}

export async function runDriftChecks(driftBox: DriftBoxLoadResult, options: RunDriftChecksOptions): Promise<DriftRunResult[]> {
    if (!driftBox.found || !driftBox.readyChecks.length) {
        return [];
    }

    const approval = await ensureApproval(driftBox, options);
    if (!approval.approved) {
        return buildNotApprovedResults(driftBox.readyChecks, approval.reason ?? 'Drift Box execution was not approved.');
    }

    const results: DriftRunResult[] = [];
    for (const check of driftBox.readyChecks) {
        results.push(await runOneCheck(check, options));
    }
    return results;
}
