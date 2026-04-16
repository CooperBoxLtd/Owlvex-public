import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

function parseMarkdownReport(markdown) {
  const lines = markdown.split(/\r?\n/);
  const files = [];
  let targetLabel;

  for (const line of lines) {
    const targetMatch = line.match(/^Target:\s+`(.+)`$/);
    if (targetMatch) {
      targetLabel = targetMatch[1];
    }
  }

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

  return { targetLabel, files };
}

function normalizeFile(value) {
  return value.replace(/\//g, '\\').trim().toLowerCase();
}

function evaluateParsedReport(report, manifest) {
  const failures = [];
  const byFile = new Map(report.files.map(entry => [normalizeFile(entry.file), entry]));
  const metrics = {
    filesChecked: manifest.expectations.length,
    expectedFindingFiles: 0,
    expectedCleanFiles: 0,
    findingFilesSatisfied: 0,
    cleanFilesSatisfied: 0,
    requiredFindingsChecked: 0,
    requiredFindingsSatisfied: 0,
    forbiddenFindingsChecked: 0,
    forbiddenFindingsSatisfied: 0,
    totalFailures: 0,
  };

  for (const expectation of manifest.expectations) {
    const reportEntry = byFile.get(normalizeFile(expectation.file));
    const findingTitles = reportEntry?.findings ?? [];

    if (expectation.expectedState === 'clean') {
      metrics.expectedCleanFiles += 1;
      if (findingTitles.length > 0) {
        failures.push(`${expectation.file}: expected clean but found ${findingTitles.join(', ')}`);
      } else {
        metrics.cleanFilesSatisfied += 1;
      }
    }

    if (expectation.expectedState === 'finding') {
      metrics.expectedFindingFiles += 1;
      if (findingTitles.length === 0) {
        failures.push(`${expectation.file}: expected at least one finding but none were reported`);
      } else {
        metrics.findingFilesSatisfied += 1;
      }
    }

    for (const title of expectation.requiredFindings ?? []) {
      metrics.requiredFindingsChecked += 1;
      if (!findingTitles.includes(title)) {
        failures.push(`${expectation.file}: missing required finding ${title}`);
      } else {
        metrics.requiredFindingsSatisfied += 1;
      }
    }

    for (const title of expectation.forbiddenFindings ?? []) {
      metrics.forbiddenFindingsChecked += 1;
      if (findingTitles.includes(title)) {
        failures.push(`${expectation.file}: forbidden finding present ${title}`);
      } else {
        metrics.forbiddenFindingsSatisfied += 1;
      }
    }
  }

  metrics.totalFailures = failures.length;

  return {
    passed: failures.length === 0,
    failures,
    metrics,
  };
}

function latestReportPath(dir) {
  return fs.readdirSync(dir)
    .filter(name => /^owlvex-scan-report-\d{8}-\d{6}\.md$/i.test(name))
    .sort()
    .at(-1);
}

function printMetrics(metrics) {
  console.log(`Files checked: ${metrics.filesChecked}`);
  console.log(`Finding expectations: ${metrics.findingFilesSatisfied}/${metrics.expectedFindingFiles}`);
  console.log(`Clean expectations: ${metrics.cleanFilesSatisfied}/${metrics.expectedCleanFiles}`);
  console.log(`Required findings: ${metrics.requiredFindingsSatisfied}/${metrics.requiredFindingsChecked}`);
  console.log(`Forbidden findings respected: ${metrics.forbiddenFindingsSatisfied}/${metrics.forbiddenFindingsChecked}`);
  console.log(`Total failures: ${metrics.totalFailures}`);
}

const profile = process.argv[2];
const explicitReportPath = process.argv[3];
const jsonMode = process.argv.includes('--json');

if (!profile || !['demo', 'demo-app'].includes(profile)) {
  console.error('Usage: node tools/evaluate-stabilization-report.mjs <demo|demo-app> [report-path] [--json]');
  process.exit(1);
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const targetDir = path.join(repoRoot, 'tools', profile);
const manifestPath = path.join(targetDir, 'benchmark.expectations.json');
const reportPath = explicitReportPath && explicitReportPath !== '--json'
  ? path.resolve(explicitReportPath)
  : path.join(targetDir, latestReportPath(targetDir) ?? '');

if (!fs.existsSync(reportPath)) {
  console.error(`No report found for ${profile}. Provide a report path explicitly or generate a fresh report first.`);
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const markdown = fs.readFileSync(reportPath, 'utf8');
const report = parseMarkdownReport(markdown);
const evaluation = evaluateParsedReport(report, manifest);

if (jsonMode) {
  console.log(JSON.stringify({
    profile,
    reportPath,
    targetLabel: report.targetLabel,
    ...evaluation,
  }, null, 2));
} else {
  console.log(`Evaluating ${profile} report: ${reportPath}`);
  printMetrics(evaluation.metrics);
}

if (!evaluation.passed) {
  if (!jsonMode) {
    console.error('Expectation check failed:');
    for (const failure of evaluation.failures) {
      console.error(`- ${failure}`);
    }
  }
  process.exit(1);
}

if (!jsonMode) {
  console.log('Expectation check passed.');
}
