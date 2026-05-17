import * as path from 'path';
import * as vscode from 'vscode';
import type { ScanResult } from './scanEngine';
import type { DesignMap } from '../designMap';

const RISK_LENS_PATH = path.join('.owlvex', 'diagrams', 'risk-lens.md');
const DESIGN_MAP_JSON_PATH = path.join('.owlvex', 'owlvex-design-map.json');

interface RiskMapEntry {
    file: string;
    result: ScanResult;
}

interface RiskLensMetadata {
    targetLabel?: string;
    skippedCount?: number;
    errors?: string[];
}

interface FindingItem {
    file: string;
    finding: ScanResult['findings'][number];
    result: ScanResult;
}

function mermaidId(prefix: string, value: string): string {
    const hash = Array.from(value).reduce((acc, char) => ((acc << 5) - acc + char.charCodeAt(0)) >>> 0, 0);
    return `${prefix}${hash.toString(16)}`;
}

function mermaidLabel(value: string, max = 80): string {
    const cleaned = value
        .replace(/\\n/g, ' ')
        .replace(/\\/g, '/')
        .replace(/"/g, "'")
        .replace(/\r?\n/g, ' ')
        .trim();
    return cleaned.length > max ? `${cleaned.slice(0, Math.max(0, max - 1))}...` : cleaned;
}

function mermaidNodeLabel(parts: string[], max = 96): string {
    return parts
        .map(part => mermaidLabel(part, max))
        .filter(Boolean)
        .join('<br/>');
}

function riskClass(score?: number): string {
    const risk = score ?? 0;
    if (risk >= 9) return 'critical';
    if (risk >= 7) return 'high';
    if (risk >= 4) return 'medium';
    return 'low';
}

function findingFamily(finding: ScanResult['findings'][number]): string {
    return finding.canonicalFamilyLabel || finding.canonicalFamily || finding.framework || 'Unclassified';
}

function findingTitle(finding: ScanResult['findings'][number]): string {
    return finding.canonicalTitle || finding.title || finding.ruleCode || 'Finding';
}

function normalizeList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return value.map(item => String(item).trim()).filter(Boolean);
    }
    if (typeof value === 'string') {
        return value
            .split(/[,\n]/)
            .map(item => item.trim())
            .filter(Boolean);
    }
    return [];
}

function normalizePath(value: string): string {
    return value.replace(/\\/g, '/');
}

function fileRole(file: string): 'runtime' | 'test' | 'dev' {
    if (/(^|\/)(test|tests|__tests__|spec)(\/|$)|\.test\.|\.spec\./i.test(file)) {
        return 'test';
    }
    if (/(^|\/)(scripts?|tools?|\.owlvex)(\/|$)|vite\.config|webpack\.config|rollup\.config/i.test(file)) {
        return 'dev';
    }
    return 'runtime';
}

function isTestOrDevFile(file: string): boolean {
    return fileRole(file) !== 'runtime';
}

async function loadDesignMap(root: vscode.Uri): Promise<DesignMap | null> {
    try {
        const raw = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(root, DESIGN_MAP_JSON_PATH));
        return JSON.parse(Buffer.from(raw).toString('utf8')) as DesignMap;
    } catch {
        return null;
    }
}

function mermaidHeader(): string[] {
    return [
        '```mermaid',
        'flowchart TD',
        '  classDef critical fill:#5a1010,stroke:#ff4d4d,color:#fff',
        '  classDef high fill:#5a3510,stroke:#ffb020,color:#fff',
        '  classDef medium fill:#3f3a12,stroke:#e6d450,color:#fff',
        '  classDef low fill:#16324a,stroke:#58a6ff,color:#fff',
        '  classDef clean fill:#12351f,stroke:#44c878,color:#fff',
        '  classDef unscanned fill:#2b2f36,stroke:#7d8590,color:#d0d7de',
        '  classDef testfile fill:#263238,stroke:#90a4ae,color:#fff',
        '  classDef evidence fill:#102d4f,stroke:#5aa9ff,color:#fff',
        '  classDef related fill:#102d4f,stroke:#5aa9ff,color:#fff',
        '',
    ];
}

function buildFixOrderMermaid(findings: FindingItem[]): string {
    const lines = mermaidHeader();
    const top = findings.slice(0, 5);
    if (!top.length) {
        lines.push('  Clean["No findings to prioritize"]:::clean');
    }
    for (const [index, item] of top.entries()) {
        const score = item.finding.riskScore ?? 0;
        const nodeId = `Fix${index + 1}`;
        lines.push(`  ${nodeId}["${mermaidNodeLabel([
            `${index + 1}. ${findingTitle(item.finding)}`,
            item.file,
            `${findingFamily(item.finding)} | risk ${score}/10`,
            `L${item.finding.line}${item.finding.lineEnd !== item.finding.line ? `-${item.finding.lineEnd}` : ''}`,
        ], 84)}"]:::${riskClass(score)}`);
        if (index > 0) {
            lines.push(`  Fix${index} --> ${nodeId}`);
        }
    }
    lines.push('```', '');
    return lines.join('\n');
}

function buildScanScopeMermaid(entries: RiskMapEntry[], findings: FindingItem[]): string {
    const findingFiles = [...new Set(findings.map(item => item.file))];
    const lines = mermaidHeader();

    for (const file of findingFiles.slice(0, 16)) {
        const fileFindings = findings.filter(item => item.file === file);
        const highest = Math.max(...fileFindings.map(item => item.finding.riskScore ?? 0));
        const fileId = mermaidId('File', file);
        const fileClass = isTestOrDevFile(file) && highest < 7 ? 'testfile' : riskClass(highest);
        lines.push(`  ${fileId}["${mermaidNodeLabel([file, fileRole(file), `risk ${highest}/10`, `${fileFindings.length} finding(s)`], 92)}"]:::${fileClass}`);
        for (const [index, item] of fileFindings.slice(0, 2).entries()) {
            const findingId = `${fileId}_Finding${index + 1}`;
            const score = item.finding.riskScore ?? 0;
            const strideValues = normalizeList(item.finding.stride);
            lines.push(`  ${findingId}["${mermaidNodeLabel([
                findingTitle(item.finding),
                findingFamily(item.finding),
                `risk ${score}/10${strideValues.length ? ` | STRIDE: ${strideValues.slice(0, 2).join(', ')}` : ''}`,
            ], 96)}"]:::${riskClass(score)}`);
            lines.push(`  ${fileId} --> ${findingId}`);

            const contract = item.finding.evidenceContract;
            if (score >= 7 && contract?.guard) {
                const guardId = `${findingId}_Guard`;
                lines.push(`  ${guardId}{"${mermaidLabel(`${contract.guard.status}: ${contract.guard.label}`, 90)}"}:::evidence`);
                lines.push(`  ${findingId} --> ${guardId}`);
            }
            if (score >= 7 && contract?.sink) {
                const sinkId = `${findingId}_Sink`;
                lines.push(`  ${sinkId}[("${mermaidLabel(contract.sink.label || contract.sink.expression, 90)}")]:::evidence`);
                lines.push(`  ${findingId} --> ${sinkId}`);
            }
        }
    }

    if (!findingFiles.length) {
        const scanned = entries.length;
        lines.push(`  Clean["${mermaidNodeLabel(['No findings in scanned scope', `${scanned} scanned file(s)`])}"]:::clean`);
    }

    lines.push('```', '');
    return lines.join('\n');
}

function buildArchitectureOverlayMermaid(entries: RiskMapEntry[], findings: FindingItem[], designMap: DesignMap): string {
    const scannedFiles = new Set(entries.map(entry => normalizePath(entry.file)));
    const riskByFile = new Map<string, { risk: number; count: number }>();
    for (const item of findings) {
        const current = riskByFile.get(item.file) ?? { risk: 0, count: 0 };
        riskByFile.set(item.file, {
            risk: Math.max(current.risk, item.finding.riskScore ?? 0),
            count: current.count + 1,
        });
    }

    const relationshipFiles = new Set<string>();
    for (const edge of designMap.relationships) {
        relationshipFiles.add(normalizePath(edge.from));
        relationshipFiles.add(normalizePath(edge.to));
    }
    const importantFiles = designMap.files
        .map(file => normalizePath(file.path))
        .filter(file => relationshipFiles.has(file) || scannedFiles.has(file) || riskByFile.has(file))
        .slice(0, 40);

    const lines = mermaidHeader();
    for (const file of importantFiles) {
        const nodeId = mermaidId('Overlay', file);
        const risk = riskByFile.get(file);
        const nodeClass = risk
            ? riskClass(risk.risk)
            : isTestOrDevFile(file) && scannedFiles.has(file)
                ? 'testfile'
            : scannedFiles.has(file)
                ? 'clean'
                : 'unscanned';
        const statusParts = risk
            ? [`risk ${risk.risk}/10`, `${risk.count} finding(s)`]
            : scannedFiles.has(file)
                ? ['scanned clean']
                : ['not scanned'];
        lines.push(`  ${nodeId}["${mermaidNodeLabel([file, fileRole(file), ...statusParts], 92)}"]:::${nodeClass}`);
    }

    const included = new Set(importantFiles);
    for (const edge of designMap.relationships.slice(0, 120)) {
        const from = normalizePath(edge.from);
        const to = normalizePath(edge.to);
        if (!included.has(from) || !included.has(to)) {
            continue;
        }
        lines.push(`  ${mermaidId('Overlay', from)} -->|${mermaidLabel(edge.kind, 24)}| ${mermaidId('Overlay', to)}`);
    }

    if (!importantFiles.length) {
        lines.push('  Empty["Design Map had no overlayable runtime relationships"]:::unscanned');
    }

    lines.push('```', '');
    return lines.join('\n');
}

function buildRiskLensMarkdown(entries: RiskMapEntry[], designMap: DesignMap | null, metadata: RiskLensMetadata = {}): string {
    const findings = entries
        .flatMap(entry => entry.result.findings.map(finding => ({ file: normalizePath(entry.file), finding, result: entry.result })))
        .sort((left, right) => (right.finding.riskScore ?? 0) - (left.finding.riskScore ?? 0));

    const lines: string[] = [
        '# Owlvex Risk Lens',
        '',
        'Generated from the latest scan. The focused view shows what this scan found. The architecture overlay uses the Design Map when available and marks unscanned files explicitly.',
        '',
        ...(metadata.targetLabel ? [`- Scan target: ${metadata.targetLabel}`] : []),
        `- Scanned files: ${entries.length}`,
        ...(metadata.skippedCount !== undefined ? [`- Skipped files: ${metadata.skippedCount}`] : []),
        ...(metadata.errors?.length ? [`- Scan errors: ${metadata.errors.length}`] : []),
        `- Files with findings: ${new Set(findings.map(item => item.file)).size}`,
        `- Total findings: ${findings.length}`,
        `- Design Map overlay: ${designMap ? 'available' : 'not available'}`,
        '',
        '## Fix Order',
        '',
        'Highest-priority findings from this scan. Start here before reading the broader overlay.',
        '',
        buildFixOrderMermaid(findings),
        '',
        '## Scan Scope View',
        '',
        'This view is limited to the latest scan target. It is the safest triage view for selected-file, changed-file, or Git-range scans.',
        '',
        buildScanScopeMermaid(entries, findings),
    ];

    lines.push('## Architecture Overlay', '');
    if (designMap) {
        lines.push('This view places the scan results on top of the broader Design Map. Gray nodes are not scanned, not clean.');
        lines.push('');
        lines.push(buildArchitectureOverlayMermaid(entries, findings, designMap));
    } else {
        lines.push('Design Map JSON was not available. Run Diagram Box once to add a full architecture overlay to the Risk Lens.');
        lines.push('');
    }
    return lines.join('\n');
}

export async function writeRiskLens(root: vscode.Uri, entries: RiskMapEntry[], metadata: RiskLensMetadata = {}): Promise<vscode.Uri | null> {
    if (!entries.length) {
        return null;
    }

    const targetUri = vscode.Uri.joinPath(root, RISK_LENS_PATH);
    await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(root, '.owlvex', 'diagrams'));
    const designMap = await loadDesignMap(root);
    const markdown = buildRiskLensMarkdown(entries, designMap, metadata);
    await vscode.workspace.fs.writeFile(targetUri, Buffer.from(markdown, 'utf8'));
    return targetUri;
}

export function getRiskLensPath(projectRootPath: string): string {
    return path.join(projectRootPath, RISK_LENS_PATH);
}
