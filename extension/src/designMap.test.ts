import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import { generateDesignMap } from './designMap';

describe('design map generator', () => {
    let tempRoot: string;

    beforeEach(() => {
        tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'owlvex-design-map-'));
        (vscode.workspace.fs.createDirectory as jest.Mock).mockResolvedValue(undefined);
        (vscode.workspace.fs.writeFile as jest.Mock).mockResolvedValue(undefined);
        (vscode.workspace.asRelativePath as jest.Mock).mockImplementation((uri: any) => String(uri?.fsPath ?? uri));
    });

    afterEach(() => {
        fs.rmSync(tempRoot, { recursive: true, force: true });
        jest.clearAllMocks();
    });

    it('extracts routes, guards, sinks, and scanner guidance from local code', async () => {
        const routesDir = path.join(tempRoot, 'src', 'routes');
        fs.mkdirSync(routesDir, { recursive: true });
        fs.writeFileSync(path.join(tempRoot, 'src', 'server.js'), [
            "const express = require('express');",
            "const app = express();",
            "app.use(requireUser);",
            "app.post('/proxy', requireUser, requireCsrf, async (req, res) => fetch(req.body.url));",
        ].join('\n'));
        fs.writeFileSync(path.join(routesDir, 'documents.js'), [
            "router.get('/:documentId', requireUser, async (req, res) => {",
            "  return repositories.documents.findForTenant(req.params.documentId, req.user.tenantId);",
            "});",
        ].join('\n'));

        const result = await generateDesignMap(vscode.Uri.file(tempRoot) as any);

        expect(result.filesScanned).toBe(2);
        expect(result.map.routes).toContain('/proxy');
        expect(result.map.guards).toContain('requireUser');
        expect(result.map.guards).toContain('requireCsrf');
        expect(result.map.sinks).toContain('fetch');
        expect(result.map.ownershipSignals).toContain('tenantId');
        expect(result.map.scannerGuidance.join('\n')).toContain('CSRF middleware appears in code');
        expect(vscode.workspace.fs.writeFile).toHaveBeenCalledTimes(8);
        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        expect(String(markdownWrite[0].fsPath)).toContain('.owlvex');
        const markdown = Buffer.from(markdownWrite[1]).toString('utf8');
        expect(markdown).toContain('# Owlvex Design Map');
        expect(markdown).toContain('```mermaid');
        expect(markdown).toContain('flowchart TD');
        expect(markdown).toContain('Application architecture');
        expect(markdown).toContain('Diagram Box Outputs');
        expect(markdown).toContain('route: src/routes/documents.js');
        expect(markdown).toContain('entrypoint: src/server.js');
        expect(result.map.entrypoints).toEqual(['src/server.js']);
    });

    it('builds module relationships and excludes dev tooling sinks from runtime aggregates', async () => {
        fs.mkdirSync(path.join(tempRoot, 'src', 'components'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'src', 'hooks'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'electron'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'scripts'), { recursive: true });

        fs.writeFileSync(path.join(tempRoot, 'src', 'main.jsx'), [
            "import App from './components/App.jsx';",
            'App();',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'components', 'App.jsx'), [
            "import { useSession } from '../hooks/useSession.js';",
            'export default function App() { return useSession(); }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'hooks', 'useSession.js'), [
            'export function useSession() {',
            '  return JSON.parse(window.localStorage.getItem("session") || "{}");',
            '}',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'electron', 'preload.js'), [
            "const { contextBridge, ipcRenderer } = require('electron');",
            "contextBridge.exposeInMainWorld('api', { ping: () => ipcRenderer.invoke('ping') });",
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'electron', 'main.js'), [
            "require('./preload');",
            "const { ipcMain } = require('electron');",
            "ipcMain.handle('ping', () => true);",
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'scripts', 'dev.mjs'), [
            "import { spawn } from 'node:child_process';",
            'spawn("node", ["--version"]);',
        ].join('\n'));

        const result = await generateDesignMap(vscode.Uri.file(tempRoot) as any);
        const relationships = result.map.relationships.map(edge => `${edge.kind}:${edge.from}->${edge.to}`);

        expect(result.map.entrypoints).toContain('src/main.jsx');
        expect(result.map.entrypoints).toContain('electron/main.js');
        expect(result.map.sinks).toContain('JSON.parse');
        expect(result.map.sinks).not.toContain('spawn');
        expect(result.map.dataStores).toContain('localStorage');
        expect(result.map.externalIntegrations).toContain('ipcRenderer.invoke');
        expect(result.map.externalIntegrations).toContain('ipcMain.handle');
        expect(relationships).toContain('imports:src/main.jsx->src/components/App.jsx');
        expect(relationships).toContain('imports:src/components/App.jsx->src/hooks/useSession.js');
        expect(relationships).toContain('imports:electron/main.js->electron/preload.js');

        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        const markdown = Buffer.from(markdownWrite[1]).toString('utf8');
        expect(markdown).toContain('frontend-entrypoint: src/main.jsx');
        expect(markdown).toContain('imports: `src/main.jsx` -> `src/components/App.jsx`');
        expect(markdown).toContain('localStorage');
        expect(markdown).toContain('ipcRenderer.invoke');
        expect(markdown).not.toContain('spawn');
        const evidenceWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls.find(call => String(call[0].fsPath).includes('security-evidence-map.md'));
        expect(evidenceWrite).toBeTruthy();
        expect(Buffer.from(evidenceWrite[1]).toString('utf8')).toContain('# Owlvex Security Evidence Map');
    });

    it('does not treat generic request or raw wording as a sink without API evidence', async () => {
        fs.mkdirSync(path.join(tempRoot, 'src'), { recursive: true });
        fs.writeFileSync(path.join(tempRoot, 'src', 'app.js'), [
            'export function describe(rawState) {',
            "  const requestLabel = 'repeat request';",
            '  return `${requestLabel}:${rawState.mode}`;',
            '}',
        ].join('\n'));

        const result = await generateDesignMap(vscode.Uri.file(tempRoot) as any);

        expect(result.map.sinks).not.toContain('request');
        expect(result.map.sinks).not.toContain('raw');
    });
});
