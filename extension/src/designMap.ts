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
    entrypoints: string[];
    routes: string[];
    guards: string[];
    sinks: string[];
    dataStores: string[];
    externalIntegrations: string[];
    confidence: 'confirmed_by_code' | 'inferred_from_naming';
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
    if (/(^|\/)(server|app|main|index)\.[cm]?[jt]sx?$/.test(normalized)) return 'entrypoint';
    if (/(^|\/)(routes?|controllers?)\//.test(normalized)) return 'route';
    if (/(^|\/)middleware\//.test(normalized)) return 'middleware';
    if (/(^|\/)(services?|lib)\//.test(normalized)) return 'service';
    if (/(^|\/)(store|repositories?|models?|data)\//.test(normalized)) return 'data-access';
    if (/(^|\/)(policies?|auth|permissions?)\//.test(normalized)) return 'policy';
    return 'source';
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
    const sinks = collectMatches(content, [
        /\b(eval|Function|child_process|exec|spawn|fetch|axios|request|jwt\.decode|jwt\.verify|JSON\.parse|deserialize|pickle|yaml\.load|fs\.(?:readFile|writeFile|createReadStream|unlink|rm)|res\.download|sendFile)\b/g,
        /\b(query|execute|raw|knex|sequelize|prisma)\b/g,
    ]);
    const dataStores = collectMatches(content, [
        /\b(repositories?|models?|collections?|tables?|prisma|sequelize|mongoose|knex|db|database|redis|mongo)\b/g,
    ]);
    const externalIntegrations = collectMatches(content, [
        /\b(fetch|axios|request|http\.request|https\.request|S3|BlobService|Stripe|Twilio|SendGrid|OpenAI|Anthropic|Azure)\b/g,
    ]);
    const entrypoints = kind === 'entrypoint' || routes.length
        ? [rel]
        : [];

    return {
        path: rel,
        kind,
        entrypoints,
        routes,
        guards,
        sinks,
        dataStores,
        externalIntegrations,
        confidence: routes.length || guards.length || sinks.length ? 'confirmed_by_code' : 'inferred_from_naming',
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
    if (map.externalIntegrations.length) {
        guidance.push('Outbound integration calls exist. SSRF-style findings should look for allowlists, URL normalization, and internal-address blocking.');
    }
    return guidance;
}

function buildMarkdown(map: DesignMap): string {
    const bullet = (values: string[], empty: string) => values.length ? values.map(value => `- ${value}`).join('\n') : `- ${empty}`;
    const fileLines = map.files.slice(0, 80).map(file => {
        const signals = [
            file.routes.length ? `routes=${file.routes.length}` : '',
            file.guards.length ? `guards=${file.guards.length}` : '',
            file.sinks.length ? `sinks=${file.sinks.length}` : '',
        ].filter(Boolean).join(', ') || 'no strong security signals';
        return `- \`${file.path}\` - ${file.kind}; ${signals}; confidence ${file.confidence}`;
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
    ].join('\n');
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

    const entrypoints = uniq(evidence.flatMap(item => item.entrypoints));
    const routes = uniq(evidence.flatMap(item => item.routes));
    const guards = uniq(evidence.flatMap(item => item.guards));
    const sinks = uniq(evidence.flatMap(item => item.sinks));
    const dataStores = uniq(evidence.flatMap(item => item.dataStores));
    const externalIntegrations = uniq(evidence.flatMap(item => item.externalIntegrations));
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
