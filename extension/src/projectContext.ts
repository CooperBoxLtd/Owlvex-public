import * as path from 'path';
import * as vscode from 'vscode';
import { PROFILE } from './profile';

const MAX_PROJECT_CONTEXT_CHARS = 8000;
const MAX_DESIGN_CONTEXT_CHARS = 10000;
const MAX_DESIGN_FILE_CHARS = 3000;
const MAX_DESIGN_FILES = 8;
const PROJECT_ROOT_SETTING = 'projectRoot';
const DEFAULT_DESIGN_CONTEXT_DIR = '.owlvex/design';

export interface ProjectContextInfo {
    combined: string;
    summary: string;
    designContext?: {
        loaded: boolean;
        files: string[];
        strideSelected: boolean;
        missingForStride: boolean;
    };
}

export interface ProjectRootInfo {
    uri?: vscode.Uri;
    summary: string;
    label: string;
    isConfigured: boolean;
}

export interface ProjectContextOptions {
    targetUris?: vscode.Uri[];
    selectedFrameworks?: string[];
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

function trimDesignContext(value: string): string {
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }

    return trimmed.length > MAX_DESIGN_FILE_CHARS
        ? `${trimmed.slice(0, MAX_DESIGN_FILE_CHARS)}\n[truncated]`
        : trimmed;
}

function frameworkSelected(frameworks: string[] | undefined, name: string): boolean {
    return Boolean(frameworks?.some(item => item.toLowerCase() === name.toLowerCase()));
}

function designPriority(fileName: string, frameworks: string[] | undefined): number {
    const normalized = fileName.toLowerCase();
    if (frameworkSelected(frameworks, 'STRIDE')) {
        if (normalized.includes('stride')) return 0;
        if (normalized.includes('trust')) return 1;
        if (normalized.includes('role') || normalized.includes('permission')) return 2;
        if (normalized.includes('data-flow') || normalized.includes('dataflow')) return 3;
    }
    if (normalized.includes('system')) return 4;
    return 5;
}

async function tryReadDesignContextDirectory(
    rootUri: vscode.Uri | undefined,
    frameworks: string[] | undefined,
): Promise<{ labels: string[]; content: string } | undefined> {
    if (!rootUri) {
        return undefined;
    }

    const designDirPath = path.join(rootUri.fsPath, DEFAULT_DESIGN_CONTEXT_DIR);
    const designDirUri = vscode.Uri.file(designDirPath);
    let entries: [string, vscode.FileType][];
    try {
        entries = await vscode.workspace.fs.readDirectory(designDirUri);
    } catch {
        return undefined;
    }
    if (!Array.isArray(entries)) {
        return undefined;
    }

    const candidateFiles = entries
        .filter(([name, type]) => Boolean(type & vscode.FileType.File) && /\.(md|txt)$/i.test(name))
        .sort((left, right) => {
            const priorityDelta = designPriority(left[0], frameworks) - designPriority(right[0], frameworks);
            return priorityDelta || left[0].localeCompare(right[0]);
        })
        .slice(0, MAX_DESIGN_FILES);

    const sections: string[] = [];
    const labels: string[] = [];
    let remainingChars = MAX_DESIGN_CONTEXT_CHARS;

    for (const [fileName] of candidateFiles) {
        if (remainingChars <= 0) {
            break;
        }

        const fileUri = vscode.Uri.file(path.join(designDirPath, fileName));
        try {
            const raw = await vscode.workspace.fs.readFile(fileUri);
            const content = trimDesignContext(Buffer.from(raw).toString('utf8'));
            if (!content) {
                continue;
            }

            const label = vscode.workspace.asRelativePath(fileUri, false);
            const section = `Design context file (${label}):\n${content}`;
            sections.push(section.slice(0, remainingChars));
            labels.push(label);
            remainingChars -= section.length;
        } catch {
            continue;
        }
    }

    if (!sections.length) {
        return undefined;
    }

    return {
        labels,
        content: sections.join('\n\n'),
    };
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
    const designContext = rootAppliesToTargets
        ? await tryReadDesignContextDirectory(projectRoot.uri, options?.selectedFrameworks)
        : undefined;
    const strideSelected = frameworkSelected(options?.selectedFrameworks, 'STRIDE');
    const rootLabel = projectRoot.summary !== 'not set' && rootAppliesToTargets ? projectRoot.label : '';
    const rootSummary = projectRoot.summary !== 'not set' && rootAppliesToTargets ? projectRoot.summary : '';
    const contextSuppressed = projectRoot.isConfigured && !rootAppliesToTargets;

    const sections = [
        rootLabel ? `Selected project root:\n${rootLabel}` : '',
        rootAppliesToTargets && legacyTeamContext ? `Legacy team/project context:\n${legacyTeamContext}` : '',
        rootAppliesToTargets && inlineProjectContext ? `Project context contract:\n${inlineProjectContext}` : '',
        rootAppliesToTargets && fileContext ? `Project context file (${fileContext.label}):\n${fileContext.content}` : '',
        rootAppliesToTargets && designContext ? `Design context:\n${designContext.content}` : '',
        contextSuppressed ? `Project context skipped:\nThe scan target is outside the configured project root (${projectRoot.label}).` : '',
    ].filter(Boolean);

    const summaryParts = [
        rootSummary ? `project root ${rootSummary}` : '',
        rootAppliesToTargets && legacyTeamContext ? 'legacy inline context' : '',
        rootAppliesToTargets && inlineProjectContext ? 'inline project contract' : '',
        rootAppliesToTargets && fileContext ? `file ${fileContext.label}` : '',
        rootAppliesToTargets && designContext ? `design context ${designContext.labels.length} file${designContext.labels.length === 1 ? '' : 's'}` : '',
        contextSuppressed ? 'configured project root skipped for out-of-root target' : '',
    ].filter(Boolean);

    return {
        combined: sections.join('\n\n'),
        summary: summaryParts.length ? summaryParts.join(' | ') : 'none',
        designContext: {
            loaded: Boolean(designContext),
            files: designContext?.labels ?? [],
            strideSelected,
            missingForStride: rootAppliesToTargets && strideSelected && !designContext,
        },
    };
}
