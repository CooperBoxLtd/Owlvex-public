import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const { DeterministicScanner } = require('../out/scanner/deterministicScanner.js');
const { getCanonicalIssueById } = require('../out/frameworks/issueResolver.js');
const { getIssueFamilyDefinition } = require('../out/frameworks/issueCatalog.js');

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const demoDir = path.join(repoRoot, 'tools', 'demo');
const scanner = new DeterministicScanner();

const severityPenalty = {
    CRITICAL: 3,
    HIGH: 2,
    MEDIUM: 1,
    LOW: 0.5,
};

const likelihoodMultiplier = {
    HIGH: 1.25,
    MEDIUM: 1,
    LOW: 0.75,
};

function timestamp() {
    const now = new Date();
    const pad = value => String(value).padStart(2, '0');
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

function getLikelihood(finding) {
    return String(finding.likelihood ?? 'MEDIUM').toUpperCase();
}

function getRiskScore(finding) {
    const matrix = {
        LOW: { LOW: 1, MEDIUM: 2, HIGH: 3 },
        MEDIUM: { LOW: 3, MEDIUM: 5, HIGH: 6 },
        HIGH: { LOW: 5, MEDIUM: 7, HIGH: 8 },
        CRITICAL: { LOW: 7, MEDIUM: 9, HIGH: 10 },
    };
    return matrix[finding.severity]?.[getLikelihood(finding)] ?? 0;
}

function calculateScore(findings) {
    const penalty = findings.reduce((total, finding) => {
        return total + (severityPenalty[finding.severity] ?? 0) * (likelihoodMultiplier[getLikelihood(finding)] ?? 1);
    }, 0);
    return Math.max(0, Number((10 - penalty).toFixed(1)));
}

function enrichFinding(finding) {
    const issue = finding.canonicalId ? getCanonicalIssueById(finding.canonicalId) : undefined;
    const family = issue?.family ? getIssueFamilyDefinition(issue.family) : undefined;
    return {
        ...finding,
        canonicalTitle: issue?.title ?? finding.title,
        canonicalFamilyLabel: family?.label,
        riskScore: getRiskScore(finding),
    };
}

function summarizeFile(result) {
    if (!result.findings.length) {
        return 'No findings detected.';
    }

    const top = result.findings
        .slice()
        .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0];
    return `${result.findings.length} finding(s), led by ${top.severity.toLowerCase()} impact / ${getLikelihood(top).toLowerCase()} likelihood ${top.canonicalTitle} (${top.riskScore}/10 risk).`;
}

const files = fs.readdirSync(demoDir)
    .filter(name => /^\d{2}-.*\.js$/.test(name))
    .sort();

const results = files.map(file => {
    const fullPath = path.join(demoDir, file);
    const source = fs.readFileSync(fullPath, 'utf8');
    const findings = scanner.scan(source, 'javascript').map(enrichFinding);
    return {
        file,
        findings,
        score: calculateScore(findings),
    };
});

const totalFindings = results.reduce((total, item) => total + item.findings.length, 0);
const avgScore = results.length
    ? (results.reduce((total, item) => total + item.score, 0) / results.length).toFixed(1)
    : '0.0';

const lines = [
    '# Owlvex Demo Report',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Files scanned: ${results.length}`,
    `Total findings: ${totalFindings}`,
    `Average score: ${avgScore}/10`,
    '',
    '## Risk Model',
    '',
    '- Score meaning: `10` is strongest, `0` is weakest.',
    '- Deterministic-only run: no AI enrichment is used in this script.',
    '- Likelihood defaults come from deterministic rule heuristics.',
    '',
    '## File Summary',
    '',
    '| File | Score | Findings | Summary |',
    '| --- | ---: | ---: | --- |',
    ...results.map(item => `| ${item.file} | ${item.score.toFixed(1)} | ${item.findings.length} | ${summarizeFile(item).replace(/\|/g, '\\|')} |`),
    '',
    '## Findings',
    '',
];

for (const result of results) {
    lines.push(`### ${result.file}`);
    if (!result.findings.length) {
        lines.push('');
        lines.push('- No findings detected.');
        lines.push('');
        continue;
    }

    for (const finding of result.findings.sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))) {
        lines.push('');
        lines.push(`- ${finding.title}`);
        lines.push(`  Impact: ${finding.severity}`);
        lines.push(`  Likelihood: ${getLikelihood(finding)}`);
        lines.push(`  Contextual risk: ${finding.riskScore}/10`);
        if (finding.canonicalFamilyLabel) {
            lines.push(`  Issue family: ${finding.canonicalFamilyLabel}`);
        }
        lines.push(`  Explanation: ${finding.explanation}`);
        lines.push(`  Fix: ${finding.fix}`);
        if ((finding.likelihoodReasons ?? []).length) {
            lines.push(`  Likelihood reasons: ${finding.likelihoodReasons.join(' | ')}`);
        }
    }
    lines.push('');
}

const outputPath = path.join(demoDir, `owlvex-scan-report-${timestamp()}.md`);
fs.writeFileSync(outputPath, `${lines.join('\n')}\n`, 'utf8');
console.log(outputPath);
