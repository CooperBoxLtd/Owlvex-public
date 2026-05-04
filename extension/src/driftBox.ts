import * as path from 'path';
import * as fs from 'fs';
import * as vscode from 'vscode';
import { PROFILE } from './profile';
import { resolveProjectRootInfo } from './projectContext';

export type DriftCheckScope = 'scan' | 'fix-preview' | 'post-fix';
export type DriftCheckStatus = 'ready' | 'disabled' | 'invalid' | 'out_of_scope';

export interface DriftCheckDefinition {
    id: string;
    label: string;
    command: string;
    frameworks: string[];
    scope: DriftCheckScope[];
    timeoutSeconds: number;
    enabled: boolean;
    commandKind?: 'script' | 'package-script';
    scriptPath?: string;
    status: DriftCheckStatus;
    reason?: string;
}

export interface DriftBoxParseResult {
    version: number;
    checks: DriftCheckDefinition[];
    readyChecks: DriftCheckDefinition[];
    warnings: string[];
    summary: string;
}

export interface DriftBoxLoadResult extends DriftBoxParseResult {
    found: boolean;
    configPath?: string;
    projectRoot?: string;
}

export interface DriftBoxParseOptions {
    projectRoot: string;
    scriptsRoot?: string;
    /**
     * Legacy compatibility only. Drift checks are custom behavior checks and
     * are no longer routed by selected security frameworks.
     */
    selectedFrameworks?: string[];
    scope?: DriftCheckScope;
}

export interface DriftBoxLoadOptions {
    selectedFrameworks?: string[];
    scope?: DriftCheckScope;
    targetUris?: vscode.Uri[];
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const MIN_TIMEOUT_SECONDS = 1;
const MAX_TIMEOUT_SECONDS = 120;
const MAX_CHECKS = 50;
const VALID_SCOPES = new Set<DriftCheckScope>(['scan', 'fix-preview', 'post-fix']);
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const SAFE_PACKAGE_SCRIPT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,79}$/;
const DISALLOWED_COMMAND_TOKENS = /(\|\||&&|[|;`<>])/;
const DRIFT_CONFIG_RELATIVE_PATH = path.join('.owlvex', 'drift', 'owlvex-drift.json');
const DRIFT_BOX_FILE_SETTING = 'driftBoxFile';
const DRIFT_SCRIPTS_ROOT_SETTING = 'driftScriptsRoot';

function asObject(value: unknown): Record<string, unknown> | undefined {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, unknown>
        : undefined;
}

function normalizeString(value: unknown, maxLength: number): string {
    return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function normalizeStringArray(value: unknown, maxItems = 20): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return [...new Set(
        value
            .filter((item): item is string => typeof item === 'string')
            .map(item => item.trim())
            .filter(Boolean),
    )].slice(0, maxItems);
}

function normalizeScopes(value: unknown): DriftCheckScope[] {
    const scopes = normalizeStringArray(value)
        .filter((item): item is DriftCheckScope => VALID_SCOPES.has(item as DriftCheckScope));
    return scopes.length ? scopes : ['scan'];
}

function normalizeTimeout(value: unknown): number {
    const numeric = typeof value === 'number' && Number.isFinite(value)
        ? value
        : DEFAULT_TIMEOUT_SECONDS;
    return Math.max(MIN_TIMEOUT_SECONDS, Math.min(MAX_TIMEOUT_SECONDS, Math.round(numeric)));
}

function isInside(parentPath: string, candidatePath: string): boolean {
    const parent = path.resolve(parentPath).toLowerCase();
    const candidate = path.resolve(candidatePath).toLowerCase();
    return candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
}

function targetUrisAreInsideRoot(targetUris: vscode.Uri[] | undefined, rootPath: string): boolean {
    if (!targetUris?.length) {
        return true;
    }

    return targetUris.every(uri => isInside(rootPath, uri.fsPath));
}

function buildSummary(found: boolean, checks: DriftCheckDefinition[], warningCount: number): string {
    if (!found) {
        return 'no drift box';
    }

    const ready = checks.filter(check => check.status === 'ready').length;
    const invalid = checks.filter(check => check.status === 'invalid').length;
    const disabled = checks.filter(check => check.status === 'disabled').length;
    const outOfScope = checks.filter(check => check.status === 'out_of_scope').length;
    const parts = [
        `${ready} ready`,
        invalid ? `${invalid} invalid` : '',
        disabled ? `${disabled} disabled` : '',
        outOfScope ? `${outOfScope} out of scope` : '',
        warningCount ? `${warningCount} warning${warningCount === 1 ? '' : 's'}` : '',
    ].filter(Boolean);

    return `drift box ${parts.join(' | ')}`;
}

function unquote(value: string): string {
    const trimmed = value.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}

function resolveConfiguredPath(value: string, projectRoot: string): string {
    const trimmed = value.trim();
    return path.isAbsolute(trimmed) ? trimmed : path.resolve(projectRoot, trimmed);
}

function extractDriftScriptPath(command: string, projectRoot: string, scriptsRoot?: string): { scriptPath?: string; normalizedCommand?: string; reason?: string } {
    if (!command || command.length > 400) {
        return { reason: 'Command is empty or too long.' };
    }
    if (DISALLOWED_COMMAND_TOKENS.test(command)) {
        return { reason: 'Command contains shell chaining, pipes, redirects, or backticks.' };
    }

    const rawParts = command.match(/"[^"]+"|'[^']+'|\S+/g) ?? [];
    const parts = rawParts.map(unquote);
    const scriptArg = parts.find(part =>
        /(^|[\\/])\.owlvex[\\/]drift[\\/]scripts[\\/]/i.test(part)
        || /\.(?:mjs|cjs|js|ts|py|ps1|sh|cmd|bat)$/i.test(part)
    );
    if (!scriptArg) {
        return { reason: 'Command must reference a script under the configured Drift scripts folder.' };
    }

    const configuredScriptsRoot = scriptsRoot?.trim()
        ? resolveConfiguredPath(scriptsRoot, projectRoot)
        : path.resolve(projectRoot, '.owlvex', 'drift', 'scripts');
    const scriptPath = path.isAbsolute(scriptArg)
        ? scriptArg
        : scriptArg.includes('/') || scriptArg.includes('\\') || scriptArg.startsWith('.')
        ? path.resolve(projectRoot, scriptArg)
        : path.resolve(configuredScriptsRoot, scriptArg);
    const rootPath = path.resolve(projectRoot);
    const driftScriptsPath = path.resolve(configuredScriptsRoot);
    if (!isInside(rootPath, scriptPath) || !isInside(driftScriptsPath, scriptPath)) {
        return { reason: 'Command script must stay inside the selected project root and configured Drift scripts folder.' };
    }

    const rawScriptArg = rawParts[parts.indexOf(scriptArg)] ?? scriptArg;
    const quotedScriptPath = scriptPath.includes(' ') ? `"${scriptPath}"` : scriptPath;
    return {
        scriptPath,
        normalizedCommand: command.replace(rawScriptArg, quotedScriptPath),
    };
}

function validatePackageScriptCommand(command: string, projectRoot: string): { normalizedCommand?: string; reason?: string } {
    if (!command || command.length > 400) {
        return { reason: 'Command is empty or too long.' };
    }
    if (DISALLOWED_COMMAND_TOKENS.test(command)) {
        return { reason: 'Command contains shell chaining, pipes, redirects, or backticks.' };
    }

    const parts = command.match(/"[^"]+"|'[^']+'|\S+/g)?.map(unquote) ?? [];
    if (parts.length !== 3 || parts[0] !== 'npm' || parts[1] !== 'run') {
        return { reason: 'Package script commands must use the form npm run <script>.' };
    }

    const scriptName = parts[2];
    if (!SAFE_PACKAGE_SCRIPT_PATTERN.test(scriptName)) {
        return { reason: 'Package script name contains unsupported characters.' };
    }

    const packageJsonPath = path.join(projectRoot, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
        return { reason: 'Package script command requires package.json in the selected project root.' };
    }

    try {
        const manifest = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        if (!manifest?.scripts || typeof manifest.scripts[scriptName] !== 'string') {
            return { reason: `package.json does not define scripts.${scriptName}.` };
        }
    } catch (error: any) {
        return { reason: `Could not read package.json scripts: ${error.message}` };
    }

    return { normalizedCommand: `npm run ${scriptName}` };
}

export function parseDriftBoxConfig(raw: string, options: DriftBoxParseOptions): DriftBoxParseResult {
    const warnings: string[] = [];
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch (error: any) {
        return {
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: [`Drift config is invalid JSON: ${error.message}`],
            summary: 'drift box invalid JSON',
        };
    }

    const root = asObject(parsed);
    if (!root) {
        return {
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: ['Drift config must be a JSON object.'],
            summary: 'drift box invalid',
        };
    }

    const version = root.version === 1 ? 1 : 0;
    if (version !== 1) {
        warnings.push('Drift config version must be 1.');
    }

    const rawChecks = Array.isArray(root.checks) ? root.checks.slice(0, MAX_CHECKS) : [];
    if (!Array.isArray(root.checks)) {
        warnings.push('Drift config checks must be an array.');
    }

    const checks = rawChecks.map((item, index): DriftCheckDefinition => {
        const check = asObject(item);
        if (!check) {
            return {
                id: `invalid-${index + 1}`,
                label: `Invalid check ${index + 1}`,
                command: '',
                frameworks: [],
                scope: ['scan'],
                timeoutSeconds: DEFAULT_TIMEOUT_SECONDS,
                enabled: false,
                status: 'invalid',
                reason: 'Check must be a JSON object.',
            };
        }

        const id = normalizeString(check.id, 80);
        const label = normalizeString(check.label, 140) || id;
        const command = normalizeString(check.command, 400);
        const frameworks = normalizeStringArray(check.frameworks);
        const scope = normalizeScopes(check.scope);
        const timeoutSeconds = normalizeTimeout(check.timeoutSeconds);
        const enabled = check.enabled !== false;

        let status: DriftCheckStatus = 'ready';
        let reason: string | undefined;
        let scriptPath: string | undefined;
        let commandKind: DriftCheckDefinition['commandKind'];
        let normalizedCommand = command;

        if (!id || !SAFE_ID_PATTERN.test(id)) {
            status = 'invalid';
            reason = 'Check id must use letters, numbers, dot, underscore, or dash and start with a letter or number.';
        } else if (!label) {
            status = 'invalid';
            reason = 'Check label is required.';
        } else if (!enabled) {
            status = 'disabled';
            reason = 'Check is disabled.';
        } else if (options.scope && !scope.includes(options.scope)) {
            status = 'out_of_scope';
            reason = `Check does not apply to ${options.scope}.`;
        } else {
            const packageScript = /^npm\s+run\s+/i.test(command);
            const extracted = packageScript
                ? validatePackageScriptCommand(command, options.projectRoot)
                : extractDriftScriptPath(command, options.projectRoot, options.scriptsRoot);
            if (!extracted.normalizedCommand && !('scriptPath' in extracted && extracted.scriptPath)) {
                status = 'invalid';
                reason = extracted.reason;
            } else {
                commandKind = packageScript ? 'package-script' : 'script';
                scriptPath = (extracted as { scriptPath?: string }).scriptPath;
                normalizedCommand = extracted.normalizedCommand ?? command;
            }
        }

        return {
            id: id || `invalid-${index + 1}`,
            label: label || `Invalid check ${index + 1}`,
            command: normalizedCommand,
            frameworks,
            scope,
            timeoutSeconds,
            enabled,
            commandKind,
            scriptPath,
            status,
            reason,
        };
    });

    for (const check of checks) {
        if (check.status === 'invalid') {
            warnings.push(`Drift check ${check.id}: ${check.reason}`);
        }
    }

    return {
        version,
        checks,
        readyChecks: checks.filter(check => check.status === 'ready'),
        warnings,
        summary: buildSummary(true, checks, warnings.length),
    };
}

export async function loadDriftBoxConfig(options?: DriftBoxLoadOptions): Promise<DriftBoxLoadResult> {
    const projectRoot = await resolveProjectRootInfo();
    if (!projectRoot.uri) {
        return {
            found: false,
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: ['Drift Box requires a workspace or selected project root.'],
            summary: 'no drift box',
        };
    }

    if (!targetUrisAreInsideRoot(options?.targetUris, projectRoot.uri.fsPath)) {
        return {
            found: false,
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: [`Drift Box skipped because the target is outside the selected project root (${projectRoot.label}).`],
            summary: 'drift box skipped for out-of-root target',
        };
    }

    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const configuredConfigPath = config.get<string>(DRIFT_BOX_FILE_SETTING, '').trim();
    const configuredScriptsRoot = config.get<string>(DRIFT_SCRIPTS_ROOT_SETTING, '').trim();
    const configPath = configuredConfigPath
        ? resolveConfiguredPath(configuredConfigPath, projectRoot.uri.fsPath)
        : path.join(projectRoot.uri.fsPath, DRIFT_CONFIG_RELATIVE_PATH);
    const configUri = vscode.Uri.file(configPath);
    let raw: Uint8Array;
    try {
        raw = await vscode.workspace.fs.readFile(configUri);
    } catch {
        return {
            found: false,
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: [],
            summary: 'no drift box',
        };
    }
    if (!(raw instanceof Uint8Array)) {
        return {
            found: false,
            version: 0,
            checks: [],
            readyChecks: [],
            warnings: [],
            summary: 'no drift box',
        };
    }

    const parsed = parseDriftBoxConfig(Buffer.from(raw).toString('utf8'), {
        projectRoot: projectRoot.uri.fsPath,
        scriptsRoot: configuredScriptsRoot || undefined,
        selectedFrameworks: options?.selectedFrameworks,
        scope: options?.scope,
    });

    return {
        found: true,
        configPath: vscode.workspace.asRelativePath(configUri, false),
        projectRoot: projectRoot.uri.fsPath,
        ...parsed,
    };
}
