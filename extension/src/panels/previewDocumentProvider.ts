import * as vscode from 'vscode';

export const OWLVEX_PREVIEW_SCHEME = 'owlvex-preview';

const previewDocuments = new Map<string, string>();

export class PreviewDocumentProvider implements vscode.TextDocumentContentProvider {
    provideTextDocumentContent(uri: vscode.Uri): string {
        return previewDocuments.get(uri.query) ?? '';
    }
}

export function createPreviewDocumentUri(label: string, content: string): vscode.Uri {
    const key = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    previewDocuments.set(key, content);
    return vscode.Uri.parse(`${OWLVEX_PREVIEW_SCHEME}:/${encodeURIComponent(label)}?${key}`);
}
