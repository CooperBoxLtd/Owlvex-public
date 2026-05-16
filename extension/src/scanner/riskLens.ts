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
        .replace(/\\/g, '/')
        .replace(/"/g, "'")
        .replace(/\r?\n/g, ' ')
        .trim();
    return cleaned.length > max ? `${cleaned.slice(0, Math.max(0, max - 1))}...` : cleaned;
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
        '  classDef evidence fill:#102d4f,stroke:#5aa9ff,color:#fff',
        '  classDef related fill:#102d4f,stroke:#5aa9ff,color:#fff',
        '',
    ];
}

function buildScanScopeMermaid(entries: RiskMapEntry[], findings: FindingItem[]): string {
    const findingFiles = [...new Set(findings.map(item => item.file))];
    const lines = mermaidHeader();

    for (const file of findingFiles.slice(0, 16)) {
        const fileFindings = findings.filter(item => item.file === file);
        const highest = Math.max(...fileFindings.map(item => item.finding.riskScore ?? 0));
        const fileId = mermaidId('File', file);
        lines.push(`  ${fileId}["${mermaidLabel(`${file}\\nrisk ${highest}/10\\n${fileFindings.length} finding(s)`, 120)}"]:::${riskClass(highest)}`);
        for (const [index, item] of fileFindings.slice(0, 3).entries()) {
            const findingId = `${fileId}_Finding${index + 1}`;
            const score = item.finding.riskScore ?? 0;
            const strideValues = normalizeList(item.finding.stride);
            const stride = strideValues.length ? `\\nSTRIDE: ${strideValues.slice(0, 2).join(', ')}` : '';
            lines.push(`  ${findingId}["${mermaidLabel(`${findingTitle(item.finding)}\\n${findingFamily(item.finding)}\\nrisk ${score}/10${stride}`, 130)}"]:::${riskClass(score)}`);
            lines.push(`  ${fileId} --> ${findingId}`);

            const contract = item.finding.evidenceContract;
            if (contract?.guard) {
                const guardId = `${findingId}_Guard`;
                lines.push(`  ${guardId}{"${mermaidLabel(`${contract.guard.status}: ${contract.guard.label}`, 90)}"}:::evidence`);
                lines.push(`  ${findingId} --> ${guardId}`);
            }
            if (contract?.sink) {
                const sinkId = `${findingId}_Sink`;
                lines.push(`  ${sinkId}[("${mermaidLabel(contract.sink.label || contract.sink.expression, 90)}")]:::evidence`);
                lines.push(`  ${findingId} --> ${sinkId}`);
            }
        }
    }

    if (!findingFiles.length) {
        const scanned = entries.length;
        lines.push(`  Clean["No findings in scanned scope\\n${scanned} scanned file(s)"]:::clean`);
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
            : scannedFiles.has(file)
                ? 'clean'
                : 'unscanned';
        const status = risk
            ? `risk ${risk.risk}/10\\n${risk.count} finding(s)`
            : scannedFiles.has(file)
                ? 'scanned clean'
                : 'not scanned';
        lines.push(`  ${nodeId}["${mermaidLabel(`${file}\\n${status}`, 110)}"]:::${nodeClass}`);
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

function buildRiskLensMarkdown(entries: RiskMapEntry[], designMap: DesignMap | null): string {
    const findings = entries
        .flatMap(entry => entry.result.findings.map(finding => ({ file: normalizePath(entry.file), finding, result: entry.result })))
        .sort((left, right) => (right.finding.riskScore ?? 0) - (left.finding.riskScore ?? 0));

    const lines: string[] = [
        '# Owlvex Risk Lens',
        '',
        'Generated from the latest scan. The focused view shows what this scan found. The architecture overlay uses the Design Map when available and marks unscanned files explicitly.',
        '',
        `- Scanned files: ${entries.length}`,
        `- Files with findings: ${new Set(findings.map(item => item.file)).size}`,
        `- Total findings: ${findings.length}`,
        `- Design Map overlay: ${designMap ? 'available' : 'not available'}`,
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

export async function writeRiskLens(root: vscode.Uri, entries: RiskMapEntry[]): Promise<vscode.Uri | null> {
    if (!entries.length) {
        return null;
    }

    const targetUri = vscode.Uri.joinPath(root, RISK_LENS_PATH);
    await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(root, '.owlvex', 'diagrams'));
    const designMap = await loadDesignMap(root);
    const markdown = buildRiskLensMarkdown(entries, designMap);
    await vscode.workspace.fs.writeFile(targetUri, Buffer.from(markdown, 'utf8'));
    return targetUri;
}

export function getRiskLensPath(projectRootPath: string): string {
    return path.join(projectRootPath, RISK_LENS_PATH);
}
