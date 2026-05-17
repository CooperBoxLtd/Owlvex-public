import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';

const DEFAULT_DESIGN_MAP_MARKDOWN = path.join('.owlvex', 'owlvex-design-map.md');
const DEFAULT_DESIGN_MAP_JSON = path.join('.owlvex', 'owlvex-design-map.json');
const DEFAULT_DIAGRAM_DIR = path.join('.owlvex', 'diagrams');
const DIAGRAM_PATHS = {
    architecture: path.join(DEFAULT_DIAGRAM_DIR, 'architecture-map.md'),
    evidence: path.join(DEFAULT_DIAGRAM_DIR, 'security-evidence-map.md'),
    threatFlow: path.join(DEFAULT_DIAGRAM_DIR, 'threat-flow.md'),
    riskLens: path.join(DEFAULT_DIAGRAM_DIR, 'risk-lens.md'),
} as const;
const MAX_FILES = 250;
const MAX_FILE_BYTES = 250_000;
const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.cs', '.java', '.rs', '.php', '.rb']);
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'out', 'build', 'coverage', '.next', '.turbo', '.venv', 'venv', '__pycache__']);

export interface DesignMapFileEvidence {
    path: string;
    kind: string;
    imports: string[];
    dependsOn: string[];
    entrypoints: string[];
    routes: string[];
    guards: string[];
    sinks: string[];
    dataStores: string[];
    externalIntegrations: string[];
    confidence: 'confirmed_by_code' | 'inferred_from_naming';
}

export interface DesignMapRelationship {
    from: string;
    to: string;
    kind: 'imports' | 'runtime-boundary' | 'route-guard' | 'route-sink';
}

export interface DesignMap {
    version: 1;
    generatedAt: string;
    projectRoot: string;
    summary: string;
    entrypoints: string[];
    routes: string[];
    guards: string[];
    sinks: string[];
    dataStores: string[];
    externalIntegrations: string[];
    ownershipSignals: string[];
    evidenceGaps: string[];
    scannerGuidance: string[];
    files: DesignMapFileEvidence[];
    relationships: DesignMapRelationship[];
}

export interface DesignMapGenerationResult {
    map: DesignMap;
    markdownUri: vscode.Uri;
    jsonUri: vscode.Uri;
    diagramUris: Record<keyof typeof DIAGRAM_PATHS, vscode.Uri>;
    filesScanned: number;
}

function isInside(root: string, target: string): boolean {
    const resolvedRoot = path.resolve(root).toLowerCase();
    const resolvedTarget = path.resolve(target).toLowerCase();
    return resolvedTarget === resolvedRoot || resolvedTarget.startsWith(`${resolvedRoot}${path.sep}`);
}

function relativePath(root: string, target: string): string {
    return path.relative(root, target).replace(/\\/g, '/');
}

function uniq(values: string[]): string[] {
    return [...new Set(values.map(value => value.trim()).filter(Boolean))];
}

function classifyFile(relative: string): string {
    const normalized = relative.toLowerCase();
    if (/(^|\/)(tests?|__tests__|spec)\//.test(normalized) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(normalized)) return 'test';
    if (/(^|\/)(scripts?|tools?)\//.test(normalized)) return 'dev-tooling';
    if (/(^|\/)electron\/main\.[cm]?[jt]s$/.test(normalized)) return 'electron-main';
    if (/(^|\/)electron\/preload\.[cm]?[jt]s$/.test(normalized)) return 'electron-preload';
    if (/(^|\/)electron\//.test(normalized)) return 'electron-runtime';
    if (/(^|\/)src\/main\.[cm]?[jt]sx?$/.test(normalized)) return 'frontend-entrypoint';
    if (/(^|\/)src\/[^/]*(terminal|app|screen|shell)\.[cm]?[jt]sx?$/.test(normalized)) return 'ui-container';
    if (/(^|\/)(components?|views?|pages?)\//.test(normalized)) return 'ui-component';
    if (/(^|\/)hooks?\//.test(normalized)) return 'hook';
    if (/(^|\/)(network|protocol)\//.test(normalized) || /protocol\.[cm]?[jt]s$/.test(normalized)) return 'protocol';
    if (/(^|\/)(utils?|helpers?)\//.test(normalized)) return 'utility';
    if (/(^|\/)(server|app|main|index)\.[cm]?[jt]sx?$/.test(normalized)) return 'entrypoint';
    if (/(^|\/)(routes?|controllers?)\//.test(normalized)) return 'route';
    if (/(^|\/)middleware\//.test(normalized)) return 'middleware';
    if (/(^|\/)(services?|lib)\//.test(normalized)) return 'service';
    if (/(^|\/)(store|repositories?|models?|data)\//.test(normalized)) return 'data-access';
    if (/(^|\/)(policies?|auth|permissions?)\//.test(normalized)) return 'policy';
    return 'source';
}

function isRuntimeFile(file: DesignMapFileEvidence): boolean {
    return !['test', 'dev-tooling'].includes(file.kind);
}

function extractLocalImports(content: string): string[] {
    return collectMatches(content, [
        /\bimport\s+(?:[^'"`]+?\s+from\s+)?['"`](\.[^'"`]+)['"`]/g,
        /\brequire\s*\(\s*['"`](\.[^'"`]+)['"`]\s*\)/g,
        /\bimport\s*\(\s*['"`](\.[^'"`]+)['"`]\s*\)/g,
    ]);
}

function resolveImportPath(fromFile: string, importPath: string, knownFiles: Set<string>): string | undefined {
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), importPath));
    const candidates = [
        base,
        ...['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].map(ext => `${base}${ext}`),
        ...['index.js', 'index.jsx', 'index.ts', 'index.tsx', 'index.mjs', 'index.cjs'].map(file => path.posix.join(base, file)),
    ];
    for (const candidate of candidates) {
        if (knownFiles.has(candidate)) {
            return candidate;
        }
    }
    return undefined;
}

function collectMatches(content: string, patterns: RegExp[]): string[] {
    const values: string[] = [];
    for (const pattern of patterns) {
        for (const match of content.matchAll(pattern)) {
            values.push(match[1] || match[0]);
        }
    }
    return uniq(values);
}

function extractFileEvidence(root: string, filePath: string, content: string): DesignMapFileEvidence {
    const rel = relativePath(root, filePath);
    const kind = classifyFile(rel);
    const routes = collectMatches(content, [
        /\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g,
        /\b(?:Fastify|fastify)\(\)?\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    ]);
    const guards = collectMatches(content, [
        /\b(requireUser|requireAuth|authenticate|authorize|can[A-Z][A-Za-z0-9_]*|requireCsrf|csrf|verify[A-Z][A-Za-z0-9_]*)\b/g,
        /\b(ALLOWED_ROLES|permissions?|roles?|tenantId|ownerId|customerId)\b/g,
    ]);
    const runtimeRelevant = !['test', 'dev-tooling'].includes(kind);
    const sinks = runtimeRelevant ? collectMatches(content, [
        /\b(eval|Function|child_process|exec|spawn|fetch|axios|jwt\.decode|jwt\.verify|JSON\.parse|deserialize|pickle|yaml\.load|fs\.(?:readFile|writeFile|createReadStream|unlink|rm)|res\.download|sendFile)\b/g,
        /\b(query|execute)\s*\(/g,
        /\.(raw)\s*\(/g,
    ]) : [];
    const dataStores = runtimeRelevant ? collectMatches(content, [
        /\b(repositories?|models?|collections?|tables?|prisma|sequelize|mongoose|knex|db|database|redis|mongo|localStorage|sessionStorage)\b/g,
    ]) : [];
    const externalIntegrations = runtimeRelevant ? collectMatches(content, [
        /\b(fetch|axios|http\.request|https\.request)\b/g,
        /\b(ipcRenderer\.invoke|ipcRenderer\.on|ipcMain\.handle|webContents\.send)\b/g,
        /\b(net\.createServer|net\.connect|socket\.write|socket\.on)\b/g,
        /\b(S3|BlobService|Stripe|Twilio|SendGrid|OpenAI|Anthropic|Azure)\b/g,
    ]) : [];
    const entrypoints = kind === 'entrypoint'
        || kind === 'frontend-entrypoint'
        || kind === 'electron-main'
        ? [rel]
        : [];

    return {
        path: rel,
        kind,
        imports: extractLocalImports(content),
        dependsOn: [],
        entrypoints,
        routes,
        guards,
        sinks,
        dataStores,
        externalIntegrations,
        confidence: routes.length || guards.length || sinks.length || dataStores.length || externalIntegrations.length ? 'confirmed_by_code' : 'inferred_from_naming',
    };
}

async function walkSourceFiles(root: string, current: string, output: string[]): Promise<void> {
    if (output.length >= MAX_FILES) {
        return;
    }

    let entries: Array<import('fs').Dirent>;
    try {
        entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
        return;
    }

    for (const entry of entries) {
        if (output.length >= MAX_FILES) {
            return;
        }
        const target = path.join(current, entry.name);
        if (!isInside(root, target)) {
            continue;
        }
        if (entry.isDirectory()) {
            if (!SKIP_DIRS.has(entry.name)) {
                await walkSourceFiles(root, target, output);
            }
            continue;
        }
        if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
            continue;
        }
        output.push(target);
    }
}

function buildGuidance(map: Omit<DesignMap, 'scannerGuidance' | 'summary'>): string[] {
    const guidance: string[] = [];
    if (map.guards.some(guard => /tenantId/i.test(guard))) {
        guidance.push('Tenant identifiers appear in code. Treat tenant scoping as a candidate ownership boundary only where guards or repository filters confirm it.');
    }
    if (map.guards.some(guard => /requireCsrf|csrf/i.test(guard))) {
        guidance.push('CSRF middleware appears in code. State-changing route findings should check whether this guard is applied before proposing fixes.');
    }
    if (map.guards.some(guard => /can[A-Z]|ALLOWED_ROLES|permission|role/i.test(guard))) {
        guidance.push('Authorization helpers or role policies appear in code. Prefer existing policy helpers over inventing new role or ownership fields.');
    }
    if (!map.ownershipSignals.length) {
        guidance.push('No strong ownership model was confirmed. Downgrade object-ownership findings to review if the only evidence is a client-supplied ID.');
    }
    if (map.externalIntegrations.some(item => /fetch|axios|http\.request|https\.request|net\.connect|net\.createServer/i.test(item))) {
        guidance.push('Outbound integration calls exist. SSRF-style findings should look for allowlists, URL normalization, and internal-address blocking.');
    }
    return guidance;
}

function mermaidId(prefix: string, index: number): string {
    return `${prefix}${index + 1}`;
}

function stableNodeId(filePath: string, index: number): string {
    return `File${index + 1}_${filePath.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 48)}`;
}

function mermaidLabel(value: string, maxLength = 56): string {
    return value
        .replace(/["\\]/g, '')
        .replace(/\s+/g, ' ')
        .slice(0, maxLength);
}

function buildMermaid(map: DesignMap): string {
    const runtimeFiles = map.files.filter(isRuntimeFile);
    const importantFiles = runtimeFiles
        .filter(file =>
            file.entrypoints.length
            || file.routes.length
            || file.guards.length
            || file.sinks.length
            || file.dataStores.length
            || file.externalIntegrations.length
            || file.dependsOn.length
            || map.relationships.some(edge => edge.to === file.path)
        )
        .slice(0, 28);
    if (importantFiles.length) {
        const nodeIds = new Map<string, string>();
        importantFiles.forEach((file, index) => nodeIds.set(file.path, stableNodeId(file.path, index)));
        const lines = [
            'flowchart TD',
            '  subgraph App["Application runtime"]',
        ];
        for (const file of importantFiles) {
            const id = nodeIds.get(file.path);
            if (!id) continue;
            lines.push(`    ${id}["${mermaidLabel(`${file.kind}: ${file.path}`, 72)}"]`);
        }
        lines.push('  end');

        const runtimeEdges = map.relationships
            .filter(edge => edge.kind === 'imports' && nodeIds.has(edge.from) && nodeIds.has(edge.to))
            .slice(0, 60);
        for (const edge of runtimeEdges) {
            lines.push(`  ${nodeIds.get(edge.from)} --> ${nodeIds.get(edge.to)}`);
        }

        const boundaryEdges = map.relationships
            .filter(edge => edge.kind === 'runtime-boundary' && nodeIds.has(edge.from) && nodeIds.has(edge.to))
            .slice(0, 20);
        for (const edge of boundaryEdges) {
            lines.push(`  ${nodeIds.get(edge.from)} -. boundary .-> ${nodeIds.get(edge.to)}`);
        }

        const guardFiles = importantFiles.filter(file => file.guards.length).slice(0, 8);
        for (const [index, file] of guardFiles.entries()) {
            const id = mermaidId('Guard', index);
            lines.push(`  ${id}{"${mermaidLabel(file.guards.slice(0, 3).join(', '))}"}`);
            lines.push(`  ${nodeIds.get(file.path)} --> ${id}`);
        }

        const sinkFiles = importantFiles.filter(file => file.sinks.length).slice(0, 8);
        for (const [index, file] of sinkFiles.entries()) {
            const id = mermaidId('Sink', index);
            lines.push(`  ${id}[("${mermaidLabel(file.sinks.slice(0, 3).join(', '))}")]`);
            lines.push(`  ${nodeIds.get(file.path)} --> ${id}`);
        }

        const storeFiles = importantFiles.filter(file => file.dataStores.length).slice(0, 8);
        for (const [index, file] of storeFiles.entries()) {
            const id = mermaidId('Store', index);
            lines.push(`  ${id}[("${mermaidLabel(file.dataStores.slice(0, 3).join(', '))}")]`);
            lines.push(`  ${nodeIds.get(file.path)} --> ${id}`);
        }

        const integrationFiles = importantFiles.filter(file => file.externalIntegrations.length).slice(0, 8);
        for (const [index, file] of integrationFiles.entries()) {
            const id = mermaidId('Integration', index);
            lines.push(`  ${id}[/"${mermaidLabel(file.externalIntegrations.slice(0, 3).join(', '))}"/]`);
            lines.push(`  ${nodeIds.get(file.path)} --> ${id}`);
        }

        return lines.join('\n');
    }

    const lines = [
        'flowchart TD',
        '  Root["Project root"]',
    ];
    const entrypoints = map.entrypoints.slice(0, 8);
    const routes = map.routes.slice(0, 12);
    const guards = map.guards.slice(0, 12);
    const sinks = map.sinks.slice(0, 12);
    const stores = map.dataStores.slice(0, 8);
    const integrations = map.externalIntegrations.slice(0, 8);

    for (const [index, value] of entrypoints.entries()) {
        lines.push(`  ${mermaidId('Entry', index)}["${mermaidLabel(value)}"]`);
        lines.push(`  Root --> ${mermaidId('Entry', index)}`);
    }
    for (const [index, value] of routes.entries()) {
        lines.push(`  ${mermaidId('Route', index)}["${mermaidLabel(value)}"]`);
        lines.push(entrypoints.length ? `  ${mermaidId('Entry', 0)} --> ${mermaidId('Route', index)}` : `  Root --> ${mermaidId('Route', index)}`);
    }
    for (const [index, value] of guards.entries()) {
        lines.push(`  ${mermaidId('Guard', index)}{"${mermaidLabel(value)}"}`);
        lines.push(routes.length ? `  ${mermaidId('Route', index % routes.length)} --> ${mermaidId('Guard', index)}` : `  Root --> ${mermaidId('Guard', index)}`);
    }
    for (const [index, value] of sinks.entries()) {
        lines.push(`  ${mermaidId('Sink', index)}[("${mermaidLabel(value)}")]`);
        lines.push(routes.length ? `  ${mermaidId('Route', index % routes.length)} --> ${mermaidId('Sink', index)}` : `  Root --> ${mermaidId('Sink', index)}`);
    }
    for (const [index, value] of stores.entries()) {
        lines.push(`  ${mermaidId('Store', index)}[("${mermaidLabel(value)}")]`);
        lines.push(routes.length ? `  ${mermaidId('Route', index % routes.length)} --> ${mermaidId('Store', index)}` : `  Root --> ${mermaidId('Store', index)}`);
    }
    for (const [index, value] of integrations.entries()) {
        lines.push(`  ${mermaidId('Integration', index)}[/"${mermaidLabel(value)}"/]`);
        lines.push(routes.length ? `  ${mermaidId('Route', index % routes.length)} --> ${mermaidId('Integration', index)}` : `  Root --> ${mermaidId('Integration', index)}`);
    }

    if (!entrypoints.length && !routes.length && !guards.length && !sinks.length && !stores.length && !integrations.length) {
        lines.push('  Root --> Unknown["No strong structure detected"]');
    }

    return lines.join('\n');
}

function buildMermaidLegend(): string {
    return [
        'Legend:',
        '',
        '- Solid arrow: confirmed import/call or scanner evidence.',
        '- Dotted arrow: inferred boundary or relationship.',
        '- Diamond: guard or policy.',
        '- Cylinder: data store.',
        '- Rounded node: security-relevant sink.',
        '- Slashed node: external integration.',
    ].join('\n');
}

function buildArchitectureMermaid(map: DesignMap): string {
    const runtimeFiles = map.files.filter(isRuntimeFile);
    const runtimeByPath = new Map(runtimeFiles.map(file => [file.path, file]));
    const findKind = (kind: string) => runtimeFiles.find(file => file.kind === kind);
    const findPath = (pattern: RegExp) => runtimeFiles.find(file => pattern.test(file.path));
    const findWith = (predicate: (file: DesignMapFileEvidence) => boolean) => runtimeFiles.find(predicate);
    const findDependency = (from: DesignMapFileEvidence | undefined, predicate: (file: DesignMapFileEvidence) => boolean): DesignMapFileEvidence | undefined => {
        if (!from) {
            return undefined;
        }
        for (const dependency of from.dependsOn) {
            const candidate = runtimeByPath.get(dependency);
            if (candidate && candidate.path !== from.path && predicate(candidate)) {
                return candidate;
            }
        }
        return undefined;
    };
    const fileLabel = (file: DesignMapFileEvidence | undefined, fallback: string, max = 78): string =>
        mermaidLabel(file ? `${fallback}: ${file.path}` : fallback, max);

    const frontendEntry = findKind('frontend-entrypoint');
    const uiContainer = findKind('ui-container') ?? findPath(/(^|\/)(App|Shell|Screen)\.[cm]?[jt]sx?$/i);
    const uiComponent = findKind('ui-component');
    const preload = findKind('electron-preload');
    const main = findKind('electron-main');
    const host = findPath(/sessionHost|server|host/i);
    const client = findPath(/sessionClient|client/i);
    const electronProtocol = runtimeFiles.find(file => file.kind === 'electron-runtime' && /protocol/i.test(file.path));
    const networkProtocol = runtimeFiles.find(file => file.kind === 'protocol');
    const networkHook = runtimeFiles.find(file => file.kind === 'hook' && /network|session/i.test(file.path));
    const outputHook = runtimeFiles.find(file => file.kind === 'hook' && /audio|player|output|render|media/i.test(file.path));
    const storageHook = runtimeFiles.find(file => file.kind === 'hook' && /persist|storage|state/i.test(file.path));
    const isFormatModule = (file: DesignMapFileEvidence) => /codec|encode|decode|serializer|parser|format/i.test(file.path);
    const isOutputModule = (file: DesignMapFileEvidence) => /audio|player|output|media|render/i.test(file.path) && file.path !== outputHook?.path;
    const formatModule = findDependency(outputHook, isFormatModule) ?? findPath(/codec|encode|decode|serializer|parser|format/i);
    const outputModule = findDependency(outputHook, isOutputModule) ?? runtimeFiles.find(isOutputModule);
    const hasElectronFlow = Boolean(frontendEntry || uiContainer || preload || main);

    if (hasElectronFlow) {
        const lines = [
            'flowchart TD',
            '  User["User"]',
        ];
        if (frontendEntry) {
            lines.push(`  User --> Frontend["${fileLabel(frontendEntry, 'React entry')}"]`);
        }
        if (uiContainer) {
            lines.push(`  ${frontendEntry ? 'Frontend' : 'User'} --> UI["${fileLabel(uiContainer, 'Main UI container')}"]`);
        }
        const uiSource = uiContainer ? 'UI' : frontendEntry ? 'Frontend' : 'User';
        if (uiComponent) {
            lines.push(`  ${uiSource} --> Controls["${fileLabel(uiComponent, 'User controls')}"]`);
        }
        if (networkHook) {
            lines.push(`  ${uiComponent ? 'Controls' : uiSource} --> SessionState["${fileLabel(networkHook, 'Network/session state')}"]`);
        }
        if (networkProtocol) {
            lines.push(`  ${networkHook ? 'SessionState' : uiSource} --> MessageProtocol["${fileLabel(networkProtocol, 'Renderer message protocol')}"]`);
        }
        if (outputHook) {
            lines.push(`  ${uiSource} --> OutputFlow["${fileLabel(outputHook, 'Domain output / playback')}"]`);
        }
        if (formatModule) {
            lines.push(`  ${outputHook ? 'OutputFlow' : uiSource} --> Format["${fileLabel(formatModule, 'Encode/decode or message format')}"]`);
        }
        if (outputModule) {
            lines.push(`  ${outputHook ? 'OutputFlow' : uiSource} --> OutputAdapter["${fileLabel(outputModule, 'Output adapter')}"]`);
        }
        if (storageHook) {
            lines.push(`  ${uiSource} --> Storage["${fileLabel(storageHook, 'Persistent state')}"]`);
            lines.push('  Storage --> LocalStorage[("localStorage")]');
        }
        if (preload) {
            lines.push(`  ${uiSource} -. renderer boundary .-> Preload["${fileLabel(preload, 'Preload API')}"]`);
        }
        if (main) {
            lines.push(`  ${preload ? 'Preload' : uiSource} -. IPC boundary .-> Main["${fileLabel(main, 'Electron main process')}"]`);
        }
        if (host) {
            lines.push(`  ${main ? 'Main' : uiSource} --> Host["${fileLabel(host, 'Session host')}"]`);
        }
        if (client) {
            lines.push(`  ${main ? 'Main' : uiSource} --> Client["${fileLabel(client, 'Session client')}"]`);
        }
        if (electronProtocol) {
            if (host) lines.push(`  Host --> WireProtocol["${fileLabel(electronProtocol, 'Wire protocol')}"]`);
            if (client) lines.push(`  Client --> WireProtocol`);
            if (!host && !client) lines.push(`  ${main ? 'Main' : uiSource} --> WireProtocol["${fileLabel(electronProtocol, 'Wire protocol')}"]`);
        }
        if (main?.externalIntegrations.some(item => /ipcMain|webContents/i.test(item))) {
            lines.push('  Main --> PrivilegedIpc[/"ipcMain.handle / webContents.send"/]');
        }
        if (preload?.externalIntegrations.some(item => /ipcRenderer/i.test(item))) {
            lines.push('  Preload --> RendererApi[/"contextBridge / ipcRenderer API"/]');
        }
        const evidenceTarget = uiContainer ? 'UI' : frontendEntry ? 'Frontend' : main ? 'Main' : 'User';
        lines.push('', '  Evidence["Raw import/sink/guard evidence stays in Security Evidence Map and JSON"]');
        lines.push(`  Evidence -. supports .-> ${evidenceTarget}`);
        return lines.join('\n');
    }

    const entryFile = findWith(file => Boolean(file.entrypoints.length)) ?? findKind('entrypoint');
    const routeFiles = runtimeFiles.filter(file => file.routes.length).slice(0, 10);
    const guardFile = findWith(file => Boolean(file.guards.length));
    const storeFile = findWith(file => Boolean(file.dataStores.length));
    const integrationFile = findWith(file => Boolean(file.externalIntegrations.length));
    const sinkFile = findWith(file => Boolean(file.sinks.length));

    if (entryFile || routeFiles.length || guardFile || storeFile || integrationFile || sinkFile) {
        const lines = [
            'flowchart TD',
            '  Actor["User / external caller"]',
            `  Actor --> Entry["${fileLabel(entryFile, 'Application entrypoint')}"]`,
        ];
        const routeSource = entryFile ? 'Entry' : 'Actor';
        for (const [index, file] of routeFiles.entries()) {
            lines.push(`  ${routeSource} --> Route${index + 1}["${fileLabel(file, `Route ${file.routes.slice(0, 2).join(', ') || index + 1}`)}"]`);
        }
        const guardedSource = routeFiles.length ? 'Route1' : routeSource;
        if (guardFile) {
            lines.push(`  ${guardedSource} --> Guard{"${fileLabel(guardFile, 'Auth / policy guard')}"} `);
        }
        const workSource = guardFile ? 'Guard' : guardedSource;
        if (storeFile) {
            lines.push(`  ${workSource} --> Store[("${fileLabel(storeFile, 'Persistence')}")]`);
        }
        if (integrationFile) {
            lines.push(`  ${workSource} --> Integration[/"${fileLabel(integrationFile, 'External integration')}"/]`);
        }
        if (sinkFile) {
            lines.push(`  ${workSource} --> SensitiveOp[("${fileLabel(sinkFile, 'Sensitive operation')}")]`);
        }
        lines.push(`  ${storeFile || integrationFile || sinkFile ? workSource : guardedSource} --> Response["Response / side effect"]`);
        lines.push('  Evidence["Raw import/sink/guard evidence stays in Security Evidence Map and JSON"]');
        lines.push('  Evidence -. supports .-> Entry');
        return lines.join('\n');
    }

    const importantFiles = runtimeFiles
        .filter(file => file.entrypoints.length || file.routes.length || file.dependsOn.length || map.relationships.some(edge => edge.to === file.path))
        .slice(0, 36);
    const selectedPaths = new Set(importantFiles.map(file => file.path));
    const nodeIds = new Map<string, string>();
    importantFiles.forEach((file, index) => nodeIds.set(file.path, stableNodeId(file.path, index)));

    const lines = [
        'flowchart TD',
        '  subgraph App["Application architecture"]',
    ];
    for (const file of importantFiles) {
        const id = nodeIds.get(file.path);
        if (!id) continue;
        lines.push(`    ${id}["${mermaidLabel(`${file.kind}: ${file.path}`, 96)}"]`);
    }
    lines.push('  end');

    const confirmedEdges = map.relationships
        .filter(edge => edge.kind === 'imports' && selectedPaths.has(edge.from) && selectedPaths.has(edge.to))
        .slice(0, 80);
    for (const edge of confirmedEdges) {
        lines.push(`  ${nodeIds.get(edge.from)} -->|confirmed import| ${nodeIds.get(edge.to)}`);
    }

    const boundaryEdges = map.relationships
        .filter(edge => edge.kind === 'runtime-boundary' && selectedPaths.has(edge.from) && selectedPaths.has(edge.to))
        .slice(0, 20);
    for (const edge of boundaryEdges) {
        lines.push(`  ${nodeIds.get(edge.from)} -. boundary .-> ${nodeIds.get(edge.to)}`);
    }

    const unlinkedGroups = uniq(runtimeFiles
        .map(file => file.path.split('/').slice(0, 2).join('/'))
        .filter(group => group && !importantFiles.some(file => file.path.startsWith(`${group}/`) || file.path === group)))
        .slice(0, 12);
    for (const [index, group] of unlinkedGroups.entries()) {
        lines.push(`  Group${index + 1}["inferred module: ${mermaidLabel(group, 48)}"]`);
    }

    if (!importantFiles.length && !unlinkedGroups.length) {
        lines.push('  AppRoot["No strong architecture relationships detected"]');
    }

    return lines.join('\n');
}

function isIdentityOrPolicyGuard(guard: string): boolean {
    return /auth|authenticate|authorize|identity|session|token|jwt|signature|verify|permission|role|csrf|tenant|owner|customer|account|organization|workspace/i.test(guard);
}

function isOwnershipSignal(signal: string): boolean {
    return /tenantId|ownerId|customerId|accountId|organizationId|orgId|workspaceId|projectId|userId/i.test(signal);
}

function isCapabilitySignal(signal: string): boolean {
    return /^can[A-Z]/.test(signal);
}

function hasNetworkIngress(file: DesignMapFileEvidence): boolean {
    return file.externalIntegrations.some(item => /socket\.on|net\.createServer/i.test(item)) || file.routes.length > 0;
}

function hasIpcIngress(file: DesignMapFileEvidence): boolean {
    return file.externalIntegrations.some(item => /ipcMain\.handle|ipcRenderer\.on|ipcRenderer\.invoke|webContents\.send/i.test(item));
}

function buildThreatFlowMermaid(map: DesignMap): string {
    const runtimeFiles = map.files.filter(isRuntimeFile);
    const rendererFile = runtimeFiles.find(file =>
        file.kind === 'frontend-entrypoint'
        || file.kind === 'ui-container'
        || file.kind === 'ui-component'
    );
    const preloadFile = runtimeFiles.find(file => file.kind === 'electron-preload');
    const mainFile = runtimeFiles.find(file => file.kind === 'electron-main');
    const routeFile = runtimeFiles.find(file => file.routes.length);
    const networkFiles = runtimeFiles.filter(hasNetworkIngress);
    const networkFile = networkFiles[0];
    const ipcFile = runtimeFiles.find(hasIpcIngress);
    const entryFile = rendererFile ?? routeFile ?? ipcFile ?? networkFile ?? mainFile ?? runtimeFiles.find(file => file.entrypoints.length);
    const identityGuardFile = runtimeFiles.find(file => file.guards.some(isIdentityOrPolicyGuard));
    const capabilityGuardFile = runtimeFiles.find(file => file.guards.some(isCapabilitySignal));
    const guardFile = identityGuardFile;
    const sinkFile = runtimeFiles.find(file => file.sinks.length);
    const storeFile = runtimeFiles.find(file => file.dataStores.length);
    const integrationFile = runtimeFiles.find(file => file.externalIntegrations.length);
    const parserFile = runtimeFiles.find(file => file.sinks.some(sink => /JSON\.parse|deserialize|pickle|yaml\.load/i.test(sink)));

    const entryLabel = entryFile ? `${entryFile.kind}: ${entryFile.path}` : 'No concrete entrypoint found';
    const guardLabel = guardFile
        ? `${guardFile.path}: ${guardFile.guards.filter(isIdentityOrPolicyGuard).slice(0, 3).join(', ')}`
        : 'No confirmed identity, policy, or message validation guard';
    const capabilityLabel = capabilityGuardFile
        ? `${capabilityGuardFile.path}: ${capabilityGuardFile.guards.filter(isCapabilitySignal).slice(0, 3).join(', ')}`
        : '';
    const parserLabel = parserFile ? `${parserFile.path}: ${parserFile.sinks.filter(sink => /JSON\.parse|deserialize|pickle|yaml\.load/i.test(sink)).slice(0, 3).join(', ')}` : 'No parser/deserialization sink found';
    const storeLabel = storeFile ? `${storeFile.path}: ${storeFile.dataStores.slice(0, 3).join(', ')}` : 'No data store found';
    const integrationLabel = integrationFile ? `${integrationFile.path}: ${integrationFile.externalIntegrations.slice(0, 3).join(', ')}` : 'No external integration found';
    const ipcLabel = ipcFile ? `${ipcFile.path}: ${ipcFile.externalIntegrations.filter(item => /ipc|webContents/i.test(item)).slice(0, 3).join(', ')}` : 'No IPC or privileged boundary found';
    const networkLabels = networkFiles.length
        ? networkFiles.slice(0, 3).map(file => `${file.path}: ${file.routes.length ? `routes ${file.routes.slice(0, 3).join(', ')}` : file.externalIntegrations.filter(item => /socket\.on|net\.createServer/i.test(item)).slice(0, 3).join(', ')}`)
        : ['No network integration found'];
    const networkLabel = networkLabels.join(' | ');
    const sinkLabel = sinkFile ? `${sinkFile.path}: ${sinkFile.sinks.slice(0, 3).join(', ')}` : 'No sensitive sink found';
    const identityLabel = identityGuardFile
        ? `${identityGuardFile.path}: ${identityGuardFile.guards.filter(isIdentityOrPolicyGuard).slice(0, 3).join(', ')}`
        : 'No concrete identity or peer-authentication evidence found';
    const auditLabel = map.files.find(file => /audit|log|history|event/i.test(file.path))?.path ?? 'No audit/logging module found';

    const lines = [
        'flowchart TD',
        '  Actor["Actor / input source"] --> Entry["Entry: ' + mermaidLabel(entryLabel, 86) + '"]',
    ];
    if (networkFile) {
        lines.push('  Peer["Network peer / external caller"] --> NetworkIngress["Network ingress: ' + mermaidLabel(networkLabel, 86) + '"]');
        if (parserFile) {
            lines.push(`  NetworkIngress --> Parser["Parser / frame decoder: ${mermaidLabel(parserLabel, 86)}"]`);
        }
    }
    if (rendererFile && preloadFile) {
        lines.push('  Entry --> RendererBoundary{"Boundary: renderer -> preload"}');
        lines.push(`  RendererBoundary --> Preload["${mermaidLabel(preloadFile.path, 74)}"]`);
        if (mainFile) {
            lines.push('  Preload --> MainBoundary{"Boundary: preload -> main process"}');
            lines.push(`  MainBoundary --> Main["${mermaidLabel(mainFile.path, 74)}"]`);
        }
    } else {
        lines.push('  Entry --> RuntimeBoundary{"Trust boundary"}');
    }
    if (networkFile) {
        lines.push(`  ${mainFile ? 'Main' : 'Entry'} --> NetworkBoundary{"Boundary: app -> network peer"}`);
        lines.push('  NetworkBoundary -. receives .-> NetworkIngress');
    }
    const primaryBoundary = networkFile
        ? (parserFile ? 'Parser' : 'NetworkIngress')
        : mainFile && preloadFile
            ? 'MainBoundary'
            : rendererFile && preloadFile
                ? 'RendererBoundary'
                : 'RuntimeBoundary';
    const privilegeBoundary = mainFile && preloadFile
        ? 'MainBoundary'
        : rendererFile && preloadFile
            ? 'RendererBoundary'
            : primaryBoundary;
    lines.push(`  ${primaryBoundary} --> Guard{"${mermaidLabel(guardLabel, 86)}"}`);
    if (capabilityLabel && !guardFile) {
        lines.push(`  Guard -. related capability .-> Capability["Capability/UI signal: ${mermaidLabel(capabilityLabel, 86)}"]`);
    }
    lines.push(
        '',
        '  subgraph Spoofing["Spoofing"]',
        `    S1["Identity / peer-auth evidence: ${mermaidLabel(identityLabel, 74)}"]`,
        '  end',
        `${networkFile ? '  NetworkIngress' : '  Guard'} --> S1`,
        '',
        '  subgraph Tampering["Tampering"]',
        `    T1["Input mutation or parser path: ${mermaidLabel(parserLabel, 74)}"]`,
        '  end',
        `  ${primaryBoundary} --> T1`,
        '',
        '  subgraph Repudiation["Repudiation"]',
        `    R1["Audit / action trace evidence: ${mermaidLabel(auditLabel, 74)}"]`,
        '  end',
        '  Guard --> R1',
        '',
        '  subgraph InformationDisclosure["Information Disclosure"]',
        `    I1["State or sensitive data path: ${mermaidLabel(storeLabel, 74)}"]`,
        '  end',
        '  Guard --> I1',
        '',
        '  subgraph DenialOfService["Denial of Service"]',
        `    D1["Network/parser pressure path: ${mermaidLabel(networkFile ? networkLabel : parserLabel, 74)}"]`,
        '  end',
        `  ${networkFile ? 'NetworkIngress' : primaryBoundary} --> D1`,
        '',
        '  subgraph ElevationOfPrivilege["Elevation of Privilege"]',
        `    E1["Privileged boundary or sink: ${mermaidLabel(ipcFile ? ipcLabel : sinkLabel, 74)}"]`,
        '  end',
        `  ${privilegeBoundary} --> E1`,
    );

    if (integrationFile) {
        lines.push(`  E1 --> Integration[/"${mermaidLabel(integrationLabel, 74)}"/]`);
    }
    if (sinkFile) {
        lines.push(`  T1 --> Sink[("${mermaidLabel(sinkLabel, 74)}")]`);
    }
    if (storeFile) {
        lines.push(`  I1 --> Store[("${mermaidLabel(storeLabel, 74)}")]`);
    }
    lines.push('  S1 --> SpoofingImpact["Review peer/user identity assumptions"]');
    lines.push('  T1 --> TamperingImpact["Review message validation and parser hardening"]');
    lines.push('  R1 --> RepudiationImpact["Review auditability of important actions"]');
    lines.push('  I1 --> InfoImpact["Review persisted or exposed sensitive state"]');
    lines.push('  D1 --> DosImpact["Review parser and message-loop resilience"]');
    lines.push('  E1 --> EopImpact["Review privileged boundary exposure"]');
    return lines.join('\n');
}

function buildDiagramMarkdown(title: string, description: string, mermaid: string): string {
    return [
        `# ${title}`,
        '',
        description,
        '',
        buildMermaidLegend(),
        '',
        '```mermaid',
        mermaid,
        '```',
        '',
    ].join('\n');
}

function buildMarkdown(map: DesignMap): string {
    const bullet = (values: string[], empty: string) => values.length ? values.map(value => `- ${value}`).join('\n') : `- ${empty}`;
    const fileLines = map.files.slice(0, 80).map(file => {
        const signals = [
            file.routes.length ? `routes=${file.routes.length}` : '',
            file.guards.length ? `guards=${file.guards.length}` : '',
            file.sinks.length ? `sinks=${file.sinks.length}` : '',
        ].filter(Boolean).join(', ') || 'no strong security signals';
        const deps = file.dependsOn.length ? `; imports ${file.dependsOn.slice(0, 5).join(', ')}` : '';
        return `- \`${file.path}\` - ${file.kind}; ${signals}${deps}; confidence ${file.confidence}`;
    });

    return [
        '# Owlvex Design Map',
        '',
        `Generated: ${map.generatedAt}`,
        `Project root: \`${map.projectRoot}\``,
        '',
        '## Project Summary',
        '',
        map.summary,
        '',
        '## Mermaid Map',
        '',
        'Copy this block into any Mermaid renderer to view the map.',
        '',
        '```mermaid',
        buildArchitectureMermaid(map),
        '```',
        '',
        '## Diagram Box Outputs',
        '',
        '- Architecture Map: `.owlvex/diagrams/architecture-map.md`',
        '- Threat Flow Diagram: `.owlvex/diagrams/threat-flow.md`',
        '- Security Evidence Map: `.owlvex/diagrams/security-evidence-map.md` (advanced evidence view)',
        '- Risk Lens: `.owlvex/diagrams/risk-lens.md` (created after scans)',
        '',
        '## Entrypoints',
        '',
        bullet(map.entrypoints, 'No entrypoints were identified.'),
        '',
        '## Routes',
        '',
        bullet(map.routes, 'No route declarations were identified.'),
        '',
        '## Guards And Policy Signals',
        '',
        bullet(map.guards, 'No guard or policy signals were identified.'),
        '',
        '## Sensitive Sinks',
        '',
        bullet(map.sinks, 'No sensitive sinks were identified.'),
        '',
        '## Data Stores',
        '',
        bullet(map.dataStores, 'No data-store signals were identified.'),
        '',
        '## External Integrations',
        '',
        bullet(map.externalIntegrations, 'No external integration calls were identified.'),
        '',
        '## Ownership / Scope Signals',
        '',
        bullet(map.ownershipSignals, 'No ownership or tenant scope model was confirmed from code.'),
        '',
        '## Evidence Gaps',
        '',
        bullet(map.evidenceGaps, 'No major evidence gaps were identified in this first-pass map.'),
        '',
        '## Scanner Guidance',
        '',
        bullet(map.scannerGuidance, 'No scanner guidance was generated.'),
        '',
        '## File Evidence',
        '',
        fileLines.join('\n') || '- No source files were mapped.',
        '',
        '## Relationships',
        '',
        map.relationships.length
            ? map.relationships.slice(0, 120).map(edge => `- ${edge.kind}: \`${edge.from}\` -> \`${edge.to}\``).join('\n')
            : '- No local module relationships were resolved.',
        '',
    ].join('\n');
}

function buildRelationships(files: DesignMapFileEvidence[]): DesignMapRelationship[] {
    const knownFiles = new Set(files.map(file => file.path));
    const byPath = new Map(files.map(file => [file.path, file]));
    const relationships: DesignMapRelationship[] = [];

    for (const file of files) {
        const resolvedImports = uniq(file.imports
            .map(importPath => resolveImportPath(file.path, importPath, knownFiles))
            .filter((item): item is string => Boolean(item)));
        file.dependsOn = resolvedImports;
        for (const dependency of resolvedImports) {
            relationships.push({ from: file.path, to: dependency, kind: 'imports' });
        }
    }

    for (const file of files) {
        if (file.kind === 'frontend-entrypoint') {
            const preload = files.find(candidate => candidate.kind === 'electron-preload');
            if (preload) relationships.push({ from: file.path, to: preload.path, kind: 'runtime-boundary' });
        }
        if (file.kind === 'electron-preload') {
            const main = files.find(candidate => candidate.kind === 'electron-main');
            if (main) relationships.push({ from: file.path, to: main.path, kind: 'runtime-boundary' });
        }
        if (file.kind === 'route') {
            for (const dependency of file.dependsOn) {
                const target = byPath.get(dependency);
                if (target?.guards.length) relationships.push({ from: file.path, to: dependency, kind: 'route-guard' });
                if (target?.sinks.length) relationships.push({ from: file.path, to: dependency, kind: 'route-sink' });
            }
        }
    }

    return uniq(relationships.map(edge => `${edge.kind}|${edge.from}|${edge.to}`))
        .map(serialized => {
            const [kind, from, to] = serialized.split('|') as [DesignMapRelationship['kind'], string, string];
            return { kind, from, to };
        });
}

export async function generateDesignMap(projectRoot: vscode.Uri): Promise<DesignMapGenerationResult> {
    const root = projectRoot.fsPath;
    const files: string[] = [];
    await walkSourceFiles(root, root, files);

    const evidence: DesignMapFileEvidence[] = [];
    for (const file of files) {
        try {
            const stat = await fs.stat(file);
            if (stat.size > MAX_FILE_BYTES) {
                continue;
            }
            const content = await fs.readFile(file, 'utf8');
            evidence.push(extractFileEvidence(root, file, content));
        } catch {
            continue;
        }
    }

    const relationships = buildRelationships(evidence);
    const runtimeEvidence = evidence.filter(isRuntimeFile);
    const entrypoints = uniq(runtimeEvidence.flatMap(item => item.entrypoints));
    const routes = uniq(runtimeEvidence.flatMap(item => item.routes));
    const guards = uniq(runtimeEvidence.flatMap(item => item.guards));
    const sinks = uniq(runtimeEvidence.flatMap(item => item.sinks));
    const sinkOccurrenceCount = runtimeEvidence.reduce((total, item) => total + item.sinks.length, 0);
    const dataStores = uniq(runtimeEvidence.flatMap(item => item.dataStores));
    const externalIntegrations = uniq(runtimeEvidence.flatMap(item => item.externalIntegrations));
    const ownershipSignals = uniq(guards.filter(isOwnershipSignal));
    const evidenceGaps = [
        !entrypoints.length ? 'No clear application entrypoint was identified.' : '',
        !guards.length ? 'No auth, authorization, CSRF, tenant, role, or policy guard signal was identified.' : '',
        !ownershipSignals.length ? 'No confirmed ownership or tenant model was identified.' : '',
    ].filter(Boolean);

    const mapWithoutSummary = {
        version: 1 as const,
        generatedAt: new Date().toISOString(),
        projectRoot: root,
        entrypoints,
        routes,
        guards,
        sinks,
        dataStores,
        externalIntegrations,
        ownershipSignals,
        evidenceGaps,
        files: evidence,
        relationships,
    };
    const scannerGuidance = buildGuidance(mapWithoutSummary);
    const summary = [
        `Mapped ${evidence.length} source file(s).`,
        entrypoints.length ? `Entrypoints identified: ${entrypoints.length}.` : 'Entrypoints were not clear from this pass.',
        routes.length ? `Route declarations identified: ${routes.length}.` : 'No route declarations were identified.',
        guards.length ? `Guard/policy signals identified: ${guards.length}.` : 'No guard/policy signals were identified.',
        sinkOccurrenceCount ? `Sensitive sink occurrences identified: ${sinkOccurrenceCount} (${sinks.length} unique type${sinks.length === 1 ? '' : 's'}).` : 'No sensitive sink signals were identified.',
    ].join(' ');

    const map: DesignMap = {
        ...mapWithoutSummary,
        summary,
        scannerGuidance,
    };

    const markdownUri = vscode.Uri.file(path.join(root, DEFAULT_DESIGN_MAP_MARKDOWN));
    const jsonUri = vscode.Uri.file(path.join(root, DEFAULT_DESIGN_MAP_JSON));
    const diagramUris: Record<keyof typeof DIAGRAM_PATHS, vscode.Uri> = {
        architecture: vscode.Uri.file(path.join(root, DIAGRAM_PATHS.architecture)),
        evidence: vscode.Uri.file(path.join(root, DIAGRAM_PATHS.evidence)),
        threatFlow: vscode.Uri.file(path.join(root, DIAGRAM_PATHS.threatFlow)),
        riskLens: vscode.Uri.file(path.join(root, DIAGRAM_PATHS.riskLens)),
    };
    await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.dirname(markdownUri.fsPath)));
    await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.join(root, DEFAULT_DIAGRAM_DIR)));
    await vscode.workspace.fs.writeFile(markdownUri, Buffer.from(buildMarkdown(map), 'utf8'));
    await vscode.workspace.fs.writeFile(jsonUri, Buffer.from(JSON.stringify(map, null, 2), 'utf8'));
    await vscode.workspace.fs.writeFile(diagramUris.architecture, Buffer.from(buildDiagramMarkdown(
        'Owlvex Architecture Map',
        'Readable module/component map. Solid edges are confirmed imports/calls; dotted edges are inferred boundaries.',
        buildArchitectureMermaid(map),
    ), 'utf8'));
    await vscode.workspace.fs.writeFile(diagramUris.evidence, Buffer.from(buildDiagramMarkdown(
        'Owlvex Security Evidence Map',
        'Scanner-grounded file, guard, sink, store, and integration evidence. This is the traceability layer.',
        buildMermaid(map),
    ), 'utf8'));
    await vscode.workspace.fs.writeFile(diagramUris.threatFlow, Buffer.from(buildDiagramMarkdown(
        'Owlvex Threat Flow Diagram',
        'STRIDE-oriented view of trust boundaries, guards, sensitive operations, stores, integrations, and possible impact paths.',
        buildThreatFlowMermaid(map),
    ), 'utf8'));
    return {
        map,
        markdownUri,
        jsonUri,
        diagramUris,
        filesScanned: evidence.length,
    };
}

export function getDefaultDesignMapMarkdownPath(projectRootPath: string): string {
    return path.join(projectRootPath, DEFAULT_DESIGN_MAP_MARKDOWN);
}

export function getDefaultDiagramMarkdownPath(projectRootPath: string, type: keyof typeof DIAGRAM_PATHS): string {
    return path.join(projectRootPath, DIAGRAM_PATHS[type]);
}
