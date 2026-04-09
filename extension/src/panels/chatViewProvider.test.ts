import * as vscode from 'vscode';
import { parseChatIntent } from './chatViewProvider';

describe('parseChatIntent', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath ?? String(uri));
    });

    it('routes repo scan report requests to report creation', () => {
        expect(parseChatIntent('scan the repo and create a report')).toEqual({
            action: 'scanReport',
            fileHint: undefined,
        });
    });

    it('routes explicit file scan requests to file scanning', () => {
        expect(parseChatIntent('scan this file')).toEqual({
            action: 'scanFile',
            fileHint: undefined,
        });
    });

    it('extracts a file path when the user names a source file', () => {
        expect(parseChatIntent('scan src/probes/owlvex-probe-safe-baseline.js')).toEqual({
            action: 'scanFile',
            fileHint: 'src/probes/owlvex-probe-safe-baseline.js',
        });
    });

    it('extracts a file-like hint from natural language', () => {
        expect(parseChatIntent('i want to scan owlex-probe-safe-baseline')).toEqual({
            action: 'scanFile',
            fileHint: 'owlex-probe-safe-baseline',
        });
    });

    it('routes folder scan requests to folder scanning', () => {
        expect(parseChatIntent('scan the workspace for issues')).toEqual({
            action: 'scanFolder',
        });
    });

    it('returns undefined for normal advisory chat', () => {
        expect(parseChatIntent('hey there')).toBeUndefined();
    });
});
