import * as path from 'path';
import * as vscode from 'vscode';
import { PROFILE } from './profile';

const MAX_PROJECT_CONTEXT_CHARS = 8000;

export interface ProjectContextInfo {
    combined: string;
    summary: string;
}

export function getProjectContextSummaryFromConfig(): string {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const legacyTeamContext = trimProjectContext(config.get<string>('teamContext', ''));
    const inlineProjectContext = trimProjectContext(config.get<string>('projectContext', ''));
    const projectContextFile = config.get<string>('projectContextFile', '').trim();

    const summaryParts = [
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

export async function loadProjectContextInfo(): Promise<ProjectContextInfo> {
    const config = vscode.workspace.getConfiguration(PROFILE.configSection);
    const legacyTeamContext = trimProjectContext(config.get<string>('teamContext', ''));
    const inlineProjectContext = trimProjectContext(config.get<string>('projectContext', ''));
    const projectContextFile = config.get<string>('projectContextFile', '');
    const fileContext = await tryReadProjectContextFile(projectContextFile);

    const sections = [
        legacyTeamContext ? `Legacy team/project context:\n${legacyTeamContext}` : '',
        inlineProjectContext ? `Project context contract:\n${inlineProjectContext}` : '',
        fileContext ? `Project context file (${fileContext.label}):\n${fileContext.content}` : '',
    ].filter(Boolean);

    const summaryParts = [
        legacyTeamContext ? 'legacy inline context' : '',
        inlineProjectContext ? 'inline project contract' : '',
        fileContext ? `file ${fileContext.label}` : '',
    ].filter(Boolean);

    return {
        combined: sections.join('\n\n'),
        summary: summaryParts.length ? summaryParts.join(' | ') : 'none',
    };
}
