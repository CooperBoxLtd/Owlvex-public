import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';

const DEFAULT_DESIGN_MAP_MARKDOWN = path.join('.owlvex', 'owlvex-design-map.md');
const DEFAULT_DESIGN_MAP_JSON = path.join('.owlvex', 'owlvex-design-map.json');
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
        buildMermaid(map),
        '```',
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
        '## Ownership Signals',
        '',
        bullet(map.ownershipSignals, 'No ownership model was confirmed from code.'),
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
    const dataStores = uniq(runtimeEvidence.flatMap(item => item.dataStores));
    const externalIntegrations = uniq(runtimeEvidence.flatMap(item => item.externalIntegrations));
    const ownershipSignals = uniq(guards.filter(item => /tenantId|ownerId|customerId|role|permission|ALLOWED_ROLES|can[A-Z]/i.test(item)));
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
        sinks.length ? `Sensitive sink signals identified: ${sinks.length}.` : 'No sensitive sink signals were identified.',
    ].join(' ');

    const map: DesignMap = {
        ...mapWithoutSummary,
        summary,
        scannerGuidance,
    };

    const markdownUri = vscode.Uri.file(path.join(root, DEFAULT_DESIGN_MAP_MARKDOWN));
    const jsonUri = vscode.Uri.file(path.join(root, DEFAULT_DESIGN_MAP_JSON));
    await vscode.workspace.fs.createDirectory(vscode.Uri.file(path.dirname(markdownUri.fsPath)));
    await vscode.workspace.fs.writeFile(markdownUri, Buffer.from(buildMarkdown(map), 'utf8'));
    await vscode.workspace.fs.writeFile(jsonUri, Buffer.from(JSON.stringify(map, null, 2), 'utf8'));

    return {
        map,
        markdownUri,
        jsonUri,
        filesScanned: evidence.length,
    };
}

export function getDefaultDesignMapMarkdownPath(projectRootPath: string): string {
    return path.join(projectRootPath, DEFAULT_DESIGN_MAP_MARKDOWN);
}
