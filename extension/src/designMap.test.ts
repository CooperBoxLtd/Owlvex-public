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
        expect(vscode.workspace.fs.writeFile).toHaveBeenCalledTimes(5);
        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        expect(String(markdownWrite[0].fsPath)).toContain('.owlvex');
        const markdown = Buffer.from(markdownWrite[1]).toString('utf8');
        expect(markdown).toContain('# Owlvex Design Map');
        expect(markdown).toContain('```mermaid');
        expect(markdown).toContain('flowchart TD');
        expect(markdown).toContain('Application entrypoint: src/server.js');
        expect(markdown).toContain('Diagram Box Outputs');
        expect(markdown).toContain('Route /:documentId: src/routes/documents.js');
        expect(markdown).toContain('Raw import/sink/guard evidence stays in Security Evidence Map and JSON');
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
        expect(markdown).toContain('React entry: src/main.jsx');
        expect(markdown).toContain('Main UI container: src/components/App.jsx');
        expect(markdown).toContain('Preload API: electron/preload.js');
        expect(markdown).toContain('Electron main process: electron/main.js');
        expect(markdown).toContain('imports: `src/main.jsx` -> `src/components/App.jsx`');
        expect(markdown).toContain('localStorage');
        expect(markdown).toContain('ipcRenderer.invoke');
        expect(markdown).not.toContain('spawn');
        const evidenceWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls.find(call => String(call[0].fsPath).includes('security-evidence-map.md'));
        expect(evidenceWrite).toBeTruthy();
        expect(Buffer.from(evidenceWrite[1]).toString('utf8')).toContain('# Owlvex Security Evidence Map');
        const threatFlowWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls.find(call => String(call[0].fsPath).includes('threat-flow.md'));
        expect(threatFlowWrite).toBeTruthy();
        const threatFlow = Buffer.from(threatFlowWrite[1]).toString('utf8');
        expect(threatFlow).toContain('subgraph Spoofing');
        expect(threatFlow).toContain('subgraph Tampering');
        expect(threatFlow).toContain('subgraph Repudiation');
        expect(threatFlow).toContain('subgraph InformationDisclosure');
        expect(threatFlow).toContain('subgraph DenialOfService');
        expect(threatFlow).toContain('subgraph ElevationOfPrivilege');
        expect(threatFlow).toContain('Boundary: renderer -> preload');
        expect(threatFlow).toContain('Boundary: preload -> main process');
        expect(threatFlow).toContain('No concrete identity or peer-authentication evidence found');
        expect(threatFlow).not.toContain('Identity / caller evidence');
        expect(threatFlow).toContain('ipcMain.handle');
        expect(threatFlow).toContain('Review privileged boundary exposure');
    });

    it('keeps architecture labels domain-neutral instead of binding to a sample app', async () => {
        fs.mkdirSync(path.join(tempRoot, 'src', 'hooks'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'src', 'utils'), { recursive: true });
        fs.writeFileSync(path.join(tempRoot, 'src', 'main.jsx'), [
            "import App from './App.jsx';",
            'App();',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'App.jsx'), [
            "import { useAudioPlayer } from './hooks/useAudioPlayer.js';",
            'export default function App() { return useAudioPlayer(); }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'hooks', 'useAudioPlayer.js'), [
            "import { encode } from '../utils/codec.js';",
            'export function useAudioPlayer() { return encode("x"); }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'utils', 'codec.js'), [
            'export function encode(value) { return value; }',
        ].join('\n'));

        await generateDesignMap(vscode.Uri.file(tempRoot) as any);

        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        const markdown = Buffer.from(markdownWrite[1]).toString('utf8');
        expect(markdown).toContain('Domain output / playback');
        expect(markdown).toContain('Encode/decode or message format');
        expect(markdown).not.toContain('Morse playback');
        expect(markdown).not.toContain('Morse encode/decode');
    });

    it('prefers confirmed output dependencies over broad protocol filename matches', async () => {
        fs.mkdirSync(path.join(tempRoot, 'src', 'hooks'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'src', 'utils'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'electron'), { recursive: true });
        fs.writeFileSync(path.join(tempRoot, 'src', 'main.jsx'), [
            "import App from './App.jsx';",
            'App();',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'App.jsx'), [
            "import { useMediaPlayer } from './hooks/useMediaPlayer.js';",
            'export default function App() { return useMediaPlayer(); }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'hooks', 'useMediaPlayer.js'), [
            "import { encode } from '../utils/codec.js';",
            "import { play } from '../utils/audioEngine.js';",
            'export function useMediaPlayer() { play(encode("x")); }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'utils', 'codec.js'), [
            'export function encode(value) { return value; }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'src', 'utils', 'audioEngine.js'), [
            'export function play(value) { return value; }',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'electron', 'protocol.js'), [
            'export function parse(value) { return JSON.parse(value); }',
        ].join('\n'));

        await generateDesignMap(vscode.Uri.file(tempRoot) as any);

        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        const markdown = Buffer.from(markdownWrite[1]).toString('utf8');
        expect(markdown).toContain('Encode/decode or message format: src/utils/codec.js');
        expect(markdown).toContain('Output adapter: src/utils/audioEngine.js');
        expect(markdown).not.toContain('Encode/decode or message format: electron/protocol.js');
        expect(markdown).not.toContain('Output adapter: src/hooks/useMediaPlayer.js');
    });

    it('models network ingress and does not promote capability flags into threat-flow guards', async () => {
        fs.mkdirSync(path.join(tempRoot, 'src', 'components'), { recursive: true });
        fs.mkdirSync(path.join(tempRoot, 'electron'), { recursive: true });
        fs.writeFileSync(path.join(tempRoot, 'src', 'components', 'Panel.jsx'), [
            'export function Panel({ canResendLast }) {',
            '  return canResendLast ? "resend" : "idle";',
            '}',
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'electron', 'main.js'), [
            "const { ipcMain } = require('electron');",
            "ipcMain.handle('send', (_event, packet) => packet);",
        ].join('\n'));
        fs.writeFileSync(path.join(tempRoot, 'electron', 'sessionHost.js'), [
            "const net = require('net');",
            "const server = net.createServer((socket) => {",
            "  socket.on('data', (chunk) => JSON.parse(chunk.toString()));",
            "  socket.write('ok');",
            "});",
        ].join('\n'));

        const result = await generateDesignMap(vscode.Uri.file(tempRoot) as any);

        expect(result.map.guards).toContain('canResendLast');
        expect(result.map.ownershipSignals).not.toContain('canResendLast');
        expect(result.map.summary).toContain('Sensitive sink occurrences identified: 1 (1 unique type).');

        const threatFlowWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls.find(call => String(call[0].fsPath).includes('threat-flow.md'));
        expect(threatFlowWrite).toBeTruthy();
        const threatFlow = Buffer.from(threatFlowWrite[1]).toString('utf8');
        expect(threatFlow).toContain('Entry: ui-component: src/components/Panel.jsx');
        expect(threatFlow).toContain('Network peer / external caller');
        expect(threatFlow).toContain('Network ingress: electron/sessionHost.js');
        expect(threatFlow).toContain('Parser / frame decoder: electron/sessionHost.js: JSON.parse');
        expect(threatFlow).toContain('No confirmed identity, policy, or message validation guard');
        expect(threatFlow).toContain('Capability/UI signal: src/components/Panel.jsx: canResendLast');
        expect(threatFlow).not.toContain('NetworkBoundary --> Guard{"src/components/Panel.jsx: canResendLast"}');
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
