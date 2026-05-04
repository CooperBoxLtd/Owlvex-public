import * as vscode from 'vscode';
import { getProjectRootSummaryFromConfig, loadProjectContextInfo, resolveProjectRootInfo } from './projectContext';

describe('project root helpers', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (vscode.workspace.workspaceFolders as any).length = 0;
        (vscode.workspace.fs.stat as jest.Mock).mockResolvedValue({ type: vscode.FileType.Directory });
        (vscode.workspace.fs.readFile as jest.Mock).mockReset();
        (vscode.workspace.fs.readDirectory as jest.Mock).mockReset();
    });

    it('uses the configured project root summary when one is stored', () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => key === 'projectRoot' ? 'D:\\repo\\service' : defaultValue),
        });

        expect(getProjectRootSummaryFromConfig()).toBe('D:\\repo\\service');
    });

    it('falls back to the first workspace folder when no project root is configured', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((_: string, defaultValue?: any) => defaultValue),
        });
        (vscode.workspace.workspaceFolders as any).push({
            name: 'service',
            uri: { fsPath: 'D:\\repo\\service', scheme: 'file', toString: () => 'D:\\repo\\service' },
        });

        const root = await resolveProjectRootInfo();
        expect(root.summary).toBe('default workspace (service)');
        expect(root.isConfigured).toBe(false);
    });

    it('skips configured project context when the scan target is outside that root', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext') {
                    return 'Benchmark app only context.';
                }
                if (key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath);

        const context = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\demo\\74-go-jwt-validation-unsafe.go')],
        });

        expect(context.summary).toBe('configured project root skipped for out-of-root target');
        expect(context.combined).toContain('Project context skipped');
        expect(context.combined).toContain('outside the configured project root');
        expect(context.combined).not.toContain('Benchmark app only context.');
    });

    it('keeps configured project context when the scan target is inside that root', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext') {
                    return 'Benchmark app only context.';
                }
                if (key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath);

        const context = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.summary).toContain('project root D:\\repo\\tools\\benchmark-app');
        expect(context.summary).toContain('inline project contract');
        expect(context.combined).toContain('Benchmark app only context.');
    });

    it('loads the configured TDD Box file only when enabled', async () => {
        const configGet = jest.fn((key: string, defaultValue?: any) => {
            if (key === 'projectRoot') {
                return 'D:\\repo\\tools\\benchmark-app';
            }
            if (key === 'projectContextFile') {
                return 'docs\\app.tdd.md';
            }
            if (key === 'tddBoxEnabled') {
                return false;
            }
            if (key === 'projectContext' || key === 'teamContext') {
                return '';
            }
            return defaultValue;
        });
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({ get: configGet });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace('D:\\repo\\tools\\benchmark-app\\', ''));
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('TDD: preserve Morse packet format.'));

        const disabledContext = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });
        expect(disabledContext.summary).not.toContain('TDD file');
        expect(disabledContext.combined).not.toContain('Morse packet format');

        configGet.mockImplementation((key: string, defaultValue?: any) => {
            if (key === 'projectRoot') {
                return 'D:\\repo\\tools\\benchmark-app';
            }
            if (key === 'projectContextFile') {
                return 'docs\\app.tdd.md';
            }
            if (key === 'tddBoxEnabled') {
                return true;
            }
            if (key === 'projectContext' || key === 'teamContext') {
                return '';
            }
            return defaultValue;
        });

        const enabledContext = await loadProjectContextInfo({
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });
        expect(enabledContext.summary).toContain('TDD file docs\\app.tdd.md');
        expect(enabledContext.combined).toContain('TDD: preserve Morse packet format.');
    });

    it('loads bounded design context from the selected project root and prioritizes STRIDE files', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext' || key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace('D:\\repo\\tools\\benchmark-app\\', ''));
        (vscode.workspace.fs.readDirectory as jest.Mock).mockResolvedValue([
            ['system.md', vscode.FileType.File],
            ['stride-notes.md', vscode.FileType.File],
            ['ignore.json', vscode.FileType.File],
            ['nested', vscode.FileType.Directory],
        ]);
        (vscode.workspace.fs.readFile as jest.Mock).mockImplementation(async (uri: any) => {
            if (uri.fsPath.endsWith('stride-notes.md')) {
                return Buffer.from('Trust boundary: browser to API.');
            }
            if (uri.fsPath.endsWith('system.md')) {
                return Buffer.from('System purpose: support portal.');
            }
            return Buffer.from('');
        });

        const context = await loadProjectContextInfo({
            selectedFrameworks: ['STRIDE'],
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.summary).toContain('design context 2 files');
        expect(context.designContext).toEqual({
            loaded: true,
            files: ['.owlvex\\design\\stride-notes.md', '.owlvex\\design\\system.md'],
            strideSelected: true,
            missingForStride: false,
        });
        expect(context.combined).toContain('Design context:');
        expect(context.combined.indexOf('stride-notes.md')).toBeLessThan(context.combined.indexOf('system.md'));
        expect(context.combined).toContain('Trust boundary: browser to API.');
        expect(context.combined).toContain('System purpose: support portal.');
        expect(context.combined).not.toContain('ignore.json');
    });

    it('loads a configured Design Box file before the default design folder', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'designContextFile') {
                    return 'docs\\security-design.md';
                }
                if (key === 'projectContext' || key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace('D:\\repo\\tools\\benchmark-app\\', ''));
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('Design file: customer ownership lives in policy.js.'));

        const context = await loadProjectContextInfo({
            selectedFrameworks: ['STRIDE'],
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.summary).toContain('design context 1 file');
        expect(context.designContext).toEqual({
            loaded: true,
            files: ['docs\\security-design.md'],
            strideSelected: true,
            missingForStride: false,
        });
        expect(context.combined).toContain('Design context file (docs\\security-design.md)');
        expect(context.combined).toContain('customer ownership lives in policy.js');
        expect(vscode.workspace.fs.readDirectory).not.toHaveBeenCalled();
    });

    it('extracts text from a configured DOCX Design Box file', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'designContextFile') {
                    return 'docs\\security-design.docx';
                }
                if (key === 'projectContext' || key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace('D:\\repo\\tools\\benchmark-app\\', ''));

        const xml = '<w:document><w:body><w:p><w:r><w:t>Trust boundary: browser to API.</w:t></w:r></w:p></w:body></w:document>';
        const fileName = Buffer.from('word/document.xml', 'utf8');
        const data = Buffer.from(xml, 'utf8');
        const header = Buffer.alloc(30);
        header.writeUInt32LE(0x04034b50, 0);
        header.writeUInt16LE(0, 8);
        header.writeUInt32LE(data.length, 18);
        header.writeUInt32LE(data.length, 22);
        header.writeUInt16LE(fileName.length, 26);
        header.writeUInt16LE(0, 28);
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.concat([header, fileName, data]));

        const context = await loadProjectContextInfo({
            selectedFrameworks: ['STRIDE'],
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.designContext?.loaded).toBe(true);
        expect(context.designContext?.files).toEqual(['docs\\security-design.docx']);
        expect(context.combined).toContain('Trust boundary: browser to API.');
        expect(vscode.workspace.fs.readDirectory).not.toHaveBeenCalled();
    });

    it('extracts simple text from a configured PDF Design Box file', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'designContextFile') {
                    return 'docs\\security-design.pdf';
                }
                if (key === 'projectContext' || key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => uri.fsPath.replace('D:\\repo\\tools\\benchmark-app\\', ''));
        (vscode.workspace.fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('%PDF\nBT\n(Trust boundary browser to API) Tj\nET\n%%EOF', 'latin1'));

        const context = await loadProjectContextInfo({
            selectedFrameworks: ['STRIDE'],
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.designContext?.loaded).toBe(true);
        expect(context.designContext?.files).toEqual(['docs\\security-design.pdf']);
        expect(context.combined).toContain('Trust boundary browser to API');
    });

    it('marks STRIDE design context as missing when no design files are loaded', async () => {
        (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
            get: jest.fn((key: string, defaultValue?: any) => {
                if (key === 'projectRoot') {
                    return 'D:\\repo\\tools\\benchmark-app';
                }
                if (key === 'projectContext' || key === 'projectContextFile' || key === 'teamContext') {
                    return '';
                }
                return defaultValue;
            }),
        });
        (vscode.workspace.fs.readDirectory as jest.Mock).mockRejectedValue(new Error('missing'));

        const context = await loadProjectContextInfo({
            selectedFrameworks: ['STRIDE'],
            targetUris: [vscode.Uri.file('D:\\repo\\tools\\benchmark-app\\src\\server.js')],
        });

        expect(context.designContext).toEqual({
            loaded: false,
            files: [],
            strideSelected: true,
            missingForStride: true,
        });
    });
});
