import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot, toolRoot } from './repo-root.mjs';

const manifestPath = path.join(toolRoot, 'manifest.json');
const templatePath = path.join(toolRoot, 'results.template.json');

function normalizeSeverity(value) {
    return String(value || '').trim().toUpperCase();
}

function verdictFromFindings(findings) {
    if (!findings.length) {
        return 'clean';
    }

    const severities = findings.map((finding) => normalizeSeverity(finding.severity));
    if (severities.every((severity) => severity === 'LOW' || severity === 'INFO' || severity === 'INFORMATIONAL')) {
        return 'advisory';
    }

    return 'vulnerable';
}

function extractRunMetadata(markdown, reportPath, defaultModel) {
    const generated = markdown.match(/^Generated:\s+(.+)$/m)?.[1]?.trim() || '';
    const frameworkLine = markdown.match(/^- Frameworks requested for this scan:\s+(.+)$/m)?.[1]?.trim() || '';
    const frameworks = [...frameworkLine.matchAll(/`([^`]+)`/g)].map((match) => match[1]);

    return {
        provider: 'ollama',
        model: defaultModel,
        date: generated ? generated.slice(0, 10) : '',
        frameworks,
        scope: path.relative(repoRoot, path.dirname(reportPath)).replaceAll('\\', '/'),
        notes: path.basename(reportPath),
    };
}

function parseDetailedFindings(markdown) {
    const lines = markdown.split(/\r?\n/);
    const findingsByFile = new Map();
    let inDetailedSection = false;
    let currentIssue = '';
    let currentFinding = null;
    let inCodeBlock = false;

    function finalizeCurrentFinding() {
        if (!currentFinding?.file) {
            currentFinding = null;
            return;
        }

        const existing = findingsByFile.get(currentFinding.file) || [];
        existing.push(currentFinding);
        findingsByFile.set(currentFinding.file, existing);
        currentFinding = null;
    }

    for (const line of lines) {
        if (line.startsWith('## Detailed Findings by Owlvex Issue')) {
            inDetailedSection = true;
            continue;
        }

        if (inDetailedSection && line.startsWith('## ') && !line.startsWith('## Detailed Findings by Owlvex Issue')) {
            finalizeCurrentFinding();
            break;
        }

        if (!inDetailedSection) {
            continue;
        }

        if (line.startsWith('```')) {
            inCodeBlock = !inCodeBlock;
            continue;
        }

        if (inCodeBlock) {
            continue;
        }

        const issueMatch = line.match(/^###\s+(.+)$/);
        if (issueMatch) {
            finalizeCurrentFinding();
            currentIssue = issueMatch[1].trim();
            continue;
        }

        const fileMatch = line.match(/^- `([^`]+)` at /);
        if (fileMatch) {
            finalizeCurrentFinding();
            currentFinding = {
                file: fileMatch[1],
                issue: currentIssue,
                severity: '',
                cwe: '',
                reasoning: '',
            };
            continue;
        }

        if (!currentFinding) {
            continue;
        }

        const severityMatch = line.match(/^\s+Severity:\s+(.+)$/);
        if (severityMatch) {
            currentFinding.severity = severityMatch[1].trim();
            continue;
        }

        const cweMatch = line.match(/^\s+Original rule code:\s+(.+)$/);
        if (cweMatch) {
            currentFinding.cwe = cweMatch[1].trim();
            continue;
        }

        const reasoningMatch = line.match(/^\s+Reasoning:\s+(.+)$/);
        if (reasoningMatch) {
            currentFinding.reasoning = reasoningMatch[1].trim();
            continue;
        }
    }

    finalizeCurrentFinding();
    return findingsByFile;
}

function makeCaseResult(caseDefinition, findings) {
    const labels = [...new Set(findings.map((finding) => finding.issue).filter(Boolean))];
    const cwes = [...new Set(findings.map((finding) => finding.cwe).filter(Boolean))];
    const findingSummaries = findings.map((finding) => [finding.issue, finding.reasoning].filter(Boolean).join(': ')).filter(Boolean);

    return {
        id: caseDefinition.id,
        verdict: verdictFromFindings(findings),
        labels,
        cwes,
        findings: findingSummaries,
        notes: findings.length ? `Imported from Owlvex markdown report for ${path.basename(caseDefinition.file)}.` : 'No findings for this benchmark file in the imported report.',
    };
}

async function main() {
    const reportPathArg = process.argv[2];
    const outputPathArg = process.argv[3];
    const modelArg = process.argv[4] || 'replace-with-model-tag';

    if (!reportPathArg) {
        throw new Error('Usage: npm run benchmark:import -- <report.md> [output.json] [model-tag]');
    }

    const reportPath = path.resolve(repoRoot, reportPathArg);
    const outputPath = outputPathArg
        ? path.resolve(repoRoot, outputPathArg)
        : path.join(toolRoot, 'runs', 'imported.results.json');

    const [manifestRaw, templateRaw, reportRaw] = await Promise.all([
        fs.readFile(manifestPath, 'utf8'),
        fs.readFile(templatePath, 'utf8'),
        fs.readFile(reportPath, 'utf8'),
    ]);

    const manifest = JSON.parse(manifestRaw);
    const template = JSON.parse(templateRaw);
    const findingsByFile = parseDetailedFindings(reportRaw);

    const output = {
        ...template,
        run: extractRunMetadata(reportRaw, reportPath, modelArg),
        cases: manifest.cases.map((caseDefinition) => makeCaseResult(caseDefinition, findingsByFile.get(path.basename(caseDefinition.file)) || [])),
    };

    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
    console.log(`Wrote benchmark results to ${path.relative(repoRoot, outputPath)}`);
}

main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
