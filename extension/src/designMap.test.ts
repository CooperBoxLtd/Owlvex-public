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
        expect(vscode.workspace.fs.writeFile).toHaveBeenCalledTimes(2);
        const markdownWrite = (vscode.workspace.fs.writeFile as jest.Mock).mock.calls[0];
        expect(String(markdownWrite[0].fsPath)).toContain('.owlvex');
        expect(Buffer.from(markdownWrite[1]).toString('utf8')).toContain('# Owlvex Design Map');
    });
});
