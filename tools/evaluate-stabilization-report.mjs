import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

function parseMarkdownReport(markdown) {
  const lines = markdown.split(/\r?\n/);
  const files = [];

  for (let index = 0; index < lines.length; index += 1) {
    const headingMatch = lines[index].match(/^###\s+(.+)$/);
    if (!headingMatch) {
      continue;
    }

    const file = headingMatch[1].trim();
    const findings = [];

    for (let inner = index + 1; inner < lines.length; inner += 1) {
      const line = lines[inner];
      if (/^###\s+/.test(line)) {
        break;
      }

      const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*.+\|\s*(?:AI|Deterministic)/);
      if (tableMatch && tableMatch[1] !== 'Finding') {
        findings.push(tableMatch[1].trim());
      }
    }

    files.push({ file, findings });
  }

  return { files };
}

function normalizeFile(value) {
  return value.replace(/\//g, '\\').trim().toLowerCase();
}

function evaluateParsedReport(report, manifest) {
  const failures = [];
  const byFile = new Map(report.files.map(entry => [normalizeFile(entry.file), entry]));

  for (const expectation of manifest.expectations) {
    const reportEntry = byFile.get(normalizeFile(expectation.file));
    const findingTitles = reportEntry?.findings ?? [];

    if (expectation.expectedState === 'clean' && findingTitles.length > 0) {
      failures.push(`${expectation.file}: expected clean but found ${findingTitles.join(', ')}`);
    }

    if (expectation.expectedState === 'finding' && findingTitles.length === 0) {
      failures.push(`${expectation.file}: expected at least one finding but none were reported`);
    }

    for (const title of expectation.requiredFindings ?? []) {
      if (!findingTitles.includes(title)) {
        failures.push(`${expectation.file}: missing required finding ${title}`);
      }
    }

    for (const title of expectation.forbiddenFindings ?? []) {
      if (findingTitles.includes(title)) {
        failures.push(`${expectation.file}: forbidden finding present ${title}`);
      }
    }
  }

  return failures;
}

function latestReportPath(dir) {
  return fs.readdirSync(dir)
    .filter(name => /^owlvex-scan-report-\d{8}-\d{6}\.md$/i.test(name))
    .sort()
    .at(-1);
}

const profile = process.argv[2];
if (!profile || !['demo', 'demo-app'].includes(profile)) {
  console.error('Usage: node tools/evaluate-stabilization-report.mjs <demo|demo-app> [report-path]');
  process.exit(1);
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const targetDir = path.join(repoRoot, 'tools', profile);
const manifestPath = path.join(targetDir, 'benchmark.expectations.json');
const explicitReportPath = process.argv[3];
const reportPath = explicitReportPath
  ? path.resolve(explicitReportPath)
  : path.join(targetDir, latestReportPath(targetDir) ?? '');

if (!fs.existsSync(reportPath)) {
  console.error(`No report found for ${profile}. Provide a report path explicitly or generate a fresh report first.`);
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const markdown = fs.readFileSync(reportPath, 'utf8');
const report = parseMarkdownReport(markdown);
const failures = evaluateParsedReport(report, manifest);

console.log(`Evaluating ${profile} report: ${reportPath}`);
if (!failures.length) {
  console.log('Expectation check passed.');
  process.exit(0);
}

console.error('Expectation check failed:');
for (const failure of failures) {
  console.error(`- ${failure}`);
}
process.exit(1);
