import * as path from 'path';
import * as vscode from 'vscode';
import { PROFILE } from './profile';

const MAX_PROJECT_CONTEXT_CHARS = 8000;
const PROJECT_ROOT_SETTING = 'projectRoot';

export interface ProjectContextInfo {
    combined: string;
    summary: string;
}

export interface ProjectRootInfo {
    uri?: vscode.Uri;
    summary: string;
    label: string;
    isConfigured: boolean;
}

export interface ProjectContextOptions {
    targetUris?: vscode.Uri[];
}

function getConfiguredProjectRootPath(): string {
    return vscode.workspace.getConfiguration(PROFILE.configSection).get<string>(PROJECT_ROOT_SETTING, '').trim();
}

function buildProjectRootLabel(uri: vscode.Uri): string {
    const relative = vscode.workspace.asRelativePath(uri, false);
    return relative && relative !== uri.fsPath ? relative : uri.fsPath;
}

async function tryResolveProjectRootUri(rootPath: string): Promise<vscode.Uri | undefined> {
    const trimmed = rootPath.trim();
    if (!trimmed) {
        return undefined;
    }

    const uri = vscode.Uri.file(trimmed);
    try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.type & vscode.FileType.Directory) {
            return uri;
        }
    } catch {
        return undefined;
    }

    return undefined;
}

function normalizePathForCompare(value: string): string {
    return path.resolve(value).toLowerCase();
}

function isPathInsideRoot(filePath: string, rootPath: string): boolean {
    const resolvedFile = normalizePathForCompare(filePath);
    const resolvedRoot = normalizePathForCompare(rootPath);
    return resolvedFile === resolvedRoot || resolvedFile.startsWith(`${resolvedRoot}${path.sep}`);
}

function targetUrisAreInsideRoot(targetUris: vscode.Uri[] | undefined, rootUri: vscode.Uri): boolean {
    if (!targetUris?.length) {
        return true;
    }

    return targetUris.every(uri => isPathInsideRoot(uri.fsPath, rootUri.fsPath));
}

export function isProjectRootConfigured(): boolean {
    return Boolean(getConfiguredProjectRootPath());
}

export function getProjectRootSummaryFromConfig(): string {
    const configured = getConfiguredProjectRootPath();
    if (configured) {
        return configured;
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    return workspaceFolder ? `default workspace (${workspaceFolder.name})` : 'not set';
}

export async function resolveProjectRootInfo(): Promise<ProjectRootInfo> {
    const configuredPath = getConfiguredProjectRootPath();
    const configuredUri = await tryResolveProjectRootUri(configuredPath);
    if (configuredUri) {
        return {
            uri: configuredUri,
            summary: buildProjectRootLabel(configuredUri),
            label: buildProjectRootLabel(configuredUri),
            isConfigured: true,
        };
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (workspaceFolder) {
        return {
            uri: workspaceFolder.uri,
            summary: `default workspace (${workspaceFolder.name})`,
            label: buildProjectRootLabel(workspaceFolder.uri),
            isConfigured: false,
        };
    }

    return {
        summary: 'not set',
        label: 'not set',
        isConfigured: false,
    };
}

export async function persistProjectRoot(uri: vscode.Uri | undefined): Promise<void> {
    await vscode.workspace
        .getConfiguration(PROFILE.configSection)
        .update(PROJECT_ROOT_SETTING, uri?.fsPath ?? '', vscode.workspace.workspaceFolders?.length
            ? vscode.ConfigurationTarget.Workspace
            : vscode.ConfigurationTarget.Global);
}

export async function promptForProjectRootSelection(options?: {
    title?: string;
    openLabel?: string;
}): Promise<ProjectRootInfo | undefined> {
    const current = await resolveProjectRootInfo();
    const picked = await vscode.window.showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: false,
        title: options?.title ?? 'Select Owlvex project root',
        openLabel: options?.openLabel ?? 'Use As Project Root',
        defaultUri: current.uri ?? vscode.workspace.workspaceFolders?.[0]?.uri,
    });

    const selected = picked?.[0];
    if (!selected) {
        return undefined;
    }

    await persistProjectRoot(selected);
    return {
        uri: selected,
        summary: buildProjectRootLabel(selected),
        label: buildProjectRootLabel(selected),
        isConfigured: true,
    };
}

export function getProjectContextSummaryFromConfig(): string {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const legacyTeamContext = trimProjectContext(config.get<string>('teamContext', ''));
    const inlineProjectContext = trimProjectContext(config.get<string>('projectContext', ''));
    const projectContextFile = config.get<string>('projectContextFile', '').trim();
    const projectRoot = getProjectRootSummaryFromConfig();

    const summaryParts = [
        projectRoot !== 'not set' ? `project root ${projectRoot}` : '',
        legacyTeamContext ? 'legacy inline context' : '',
        inlineProjectContext ? 'inline project contract' : '',
        projectContextFile ? `file ${projectContextFile}` : '',
    ].filter(Boolean);

    return summaryParts.length ? summaryParts.join(' | ') : 'none';
}

function trimProjectContext(value: string): string {
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }

    return trimmed.length > MAX_PROJECT_CONTEXT_CHARS
        ? `${trimmed.slice(0, MAX_PROJECT_CONTEXT_CHARS)}\n[truncated]`
        : trimmed;
}

async function tryReadProjectContextFile(fileSetting: string): Promise<{ label: string; content: string } | undefined> {
    const trimmed = fileSetting.trim();
    if (!trimmed) {
        return undefined;
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const fsPath = path.isAbsolute(trimmed)
        ? trimmed
        : workspaceFolder
        ? path.join(workspaceFolder.uri.fsPath, trimmed)
        : undefined;

    if (!fsPath) {
        return undefined;
    }

    try {
        const raw = await vscode.workspace.fs.readFile(vscode.Uri.file(fsPath));
        const content = trimProjectContext(Buffer.from(raw).toString('utf8'));
        if (!content) {
            return undefined;
        }

        return {
            label: vscode.workspace.asRelativePath(vscode.Uri.file(fsPath), false),
            content,
        };
    } catch {
        return undefined;
    }
}

export async function loadProjectContextInfo(options?: ProjectContextOptions): Promise<ProjectContextInfo> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const legacyTeamContext = trimProjectContext(config.get<string>('teamContext', ''));
    const inlineProjectContext = trimProjectContext(config.get<string>('projectContext', ''));
    const projectContextFile = config.get<string>('projectContextFile', '');
    const fileContext = await tryReadProjectContextFile(projectContextFile);
    const projectRoot = await resolveProjectRootInfo();
    const rootAppliesToTargets = !projectRoot.uri || targetUrisAreInsideRoot(options?.targetUris, projectRoot.uri);
    const rootLabel = projectRoot.summary !== 'not set' && rootAppliesToTargets ? projectRoot.label : '';
    const rootSummary = projectRoot.summary !== 'not set' && rootAppliesToTargets ? projectRoot.summary : '';
    const contextSuppressed = projectRoot.isConfigured && !rootAppliesToTargets;

    const sections = [
        rootLabel ? `Selected project root:\n${rootLabel}` : '',
        rootAppliesToTargets && legacyTeamContext ? `Legacy team/project context:\n${legacyTeamContext}` : '',
        rootAppliesToTargets && inlineProjectContext ? `Project context contract:\n${inlineProjectContext}` : '',
        rootAppliesToTargets && fileContext ? `Project context file (${fileContext.label}):\n${fileContext.content}` : '',
        contextSuppressed ? `Project context skipped:\nThe scan target is outside the configured project root (${projectRoot.label}).` : '',
    ].filter(Boolean);

    const summaryParts = [
        rootSummary ? `project root ${rootSummary}` : '',
        rootAppliesToTargets && legacyTeamContext ? 'legacy inline context' : '',
        rootAppliesToTargets && inlineProjectContext ? 'inline project contract' : '',
        rootAppliesToTargets && fileContext ? `file ${fileContext.label}` : '',
        contextSuppressed ? 'configured project root skipped for out-of-root target' : '',
    ].filter(Boolean);

    return {
        combined: sections.join('\n\n'),
        summary: summaryParts.length ? summaryParts.join(' | ') : 'none',
    };
}
