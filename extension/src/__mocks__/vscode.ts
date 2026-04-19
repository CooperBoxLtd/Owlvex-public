/**
 * Minimal VS Code API mock for Jest unit tests.
 * Only the parts actually used by the tested modules are mocked.
 */

export const window = {
    showInformationMessage: jest.fn(),
    showErrorMessage: jest.fn(),
    showWarningMessage: jest.fn(),
    showInputBox: jest.fn(),
    showQuickPick: jest.fn(),
    showOpenDialog: jest.fn(),
    showTextDocument: jest.fn(),
    activeTextEditor: undefined as any,
    createWebviewPanel: jest.fn(),
    createStatusBarItem: jest.fn(),
    withProgress: jest.fn(),
};

const workspaceFoldersState: any[] = [];

export const workspace: any = {
    getConfiguration: jest.fn(() => ({
        get: jest.fn((key: string, defaultValue?: any) => defaultValue),
        update: jest.fn(),
    })),
    onDidSaveTextDocument: jest.fn(),
    textDocuments: [],
    findFiles: jest.fn(),
    openTextDocument: jest.fn(),
    applyEdit: jest.fn(),
    asRelativePath: jest.fn((uri: any) => String(uri)),
    workspaceFolders: workspaceFoldersState,
    getWorkspaceFolder: jest.fn((uri: any) => {
        const filePath = String(uri?.fsPath ?? '');
        return workspaceFoldersState.find(folder => filePath.toLowerCase().startsWith(String(folder?.uri?.fsPath ?? '').toLowerCase()));
    }),
    fs: {
        readFile: jest.fn(),
        readDirectory: jest.fn(),
        writeFile: jest.fn(),
    },
};

export const commands = {
    registerCommand: jest.fn(),
    executeCommand: jest.fn(),
};

export const extensions = {
    getExtension: jest.fn(() => ({
        exports: { secrets: { get: jest.fn(), store: jest.fn(), delete: jest.fn() } },
    })),
};

export const ProgressLocation = { Notification: 15, SourceControl: 1, Window: 10 };
export const StatusBarAlignment = { Left: 1, Right: 2 };
export const ConfigurationTarget = { Global: 1, Workspace: 2, WorkspaceFolder: 3 };
export class ThemeColor {
    constructor(public id: string) {}
}
export class ThemeIcon {
    constructor(public id: string) {}
}

export class Position {
    constructor(public line: number, public character: number) {}
}

export class Range {
    constructor(public start: Position, public end: Position) {}
}

export class Selection extends Range {
    constructor(anchor: Position, active: Position) { super(anchor, active); }
}

export const TextEditorRevealType = { InCenter: 2 };
export const FileType = { Unknown: 0, File: 1, Directory: 2, SymbolicLink: 64 };

export class DiagnosticCollection {
    set = jest.fn();
    delete = jest.fn();
    clear = jest.fn();
    dispose = jest.fn();
}

export const languages = {
    createDiagnosticCollection: jest.fn(() => new DiagnosticCollection()),
};

export class Diagnostic {
    constructor(
        public range: Range,
        public message: string,
        public severity: number,
    ) {}
    source?: string;
    code?: string;
}

export const DiagnosticSeverity = { Error: 0, Warning: 1, Information: 2, Hint: 3 };

export class Uri {
    static file(path: string) { return { fsPath: path, toString: () => path, scheme: 'file' }; }
    static joinPath(base: any, ...segments: string[]) {
        const joined = [base.fsPath, ...segments].join('\\');
        return { fsPath: joined, toString: () => joined, scheme: 'file' };
    }
    static parse(value: string) { return { fsPath: value, toString: () => value, scheme: value.includes(':') ? 'file' : '' }; }
}

export class WorkspaceEdit {
    entries: Array<{ uri: any; range: Range; text: string }> = [];

    replace(uri: any, range: Range, text: string) {
        this.entries.push({ uri, range, text });
    }
}

export class EventEmitter {
    event = jest.fn();
    fire = jest.fn();
    dispose = jest.fn();
}

export class TreeItem {
    constructor(public label: string, public collapsibleState?: number) {}
}

export const TreeItemCollapsibleState = { None: 0, Collapsed: 1, Expanded: 2 };

export class ViewColumn { static One = 1; }

export class StatusBarItem {
    text = '';
    tooltip: string | undefined;
    command: string | undefined;
    backgroundColor: any;
    show = jest.fn();
    dispose = jest.fn();
}

window.createStatusBarItem.mockImplementation(() => new StatusBarItem());
