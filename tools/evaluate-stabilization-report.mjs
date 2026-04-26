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
    const detections = [];
    const evidenceIssueTypes = [];
    const proofStatuses = [];
    let primaryScanMode;
    let scanTierPosture;
    let corroborationPosture;
    let proofPosture;

    for (let inner = index + 1; inner < lines.length; inner += 1) {
      const line = lines[inner];
      if (/^###\s+/.test(line)) {
        break;
      }

      const primaryScanModeMatch = line.match(/^-\s+(?:Primary scan mode|Analysis mode):\s+(.+)$/);
      if (primaryScanModeMatch && !primaryScanMode) {
        primaryScanMode = primaryScanModeMatch[1].trim();
      }

      const scanTierPostureMatch = line.match(/^-\s+(?:Scan tier posture|Analysis mix):\s+(.+)$/);
      if (scanTierPostureMatch && !scanTierPosture) {
        scanTierPosture = scanTierPostureMatch[1].trim();
      }

      const corroborationPostureMatch = line.match(/^-\s+(?:Corroboration posture|Evidence):\s+(.+)$/);
      if (corroborationPostureMatch && !corroborationPosture) {
        corroborationPosture = corroborationPostureMatch[1].trim();
      }

      const proofPostureMatch = line.match(/^-\s+Proof posture:\s+(.+)$/);
      if (proofPostureMatch && !proofPosture) {
        proofPosture = proofPostureMatch[1].trim();
      }

      const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*.+\|\s*(.+?)\s*\|$/);
      if (tableMatch && tableMatch[1] !== 'Finding') {
        findings.push(tableMatch[1].trim());
        detections.push(tableMatch[2].trim());
      }

      const evidenceContractMatch = line.match(/^-\s+Evidence contract:\s+\w+\s+(.+)$/);
      if (evidenceContractMatch) {
        evidenceIssueTypes.push(evidenceContractMatch[1].trim());
      }

      const proofStatusMatch = line.match(/^-\s+Proof status:\s+(.+)$/);
      if (proofStatusMatch) {
        proofStatuses.push(proofStatusMatch[1].trim());
      }
    }

    files.push({
      file,
      findings,
      detections,
      evidenceIssueTypes,
      proofStatuses,
      primaryScanMode,
      scanTierPosture,
      corroborationPosture,
      proofPosture,
    });
  }

  return { targetLabel, files };
}

function normalizeFile(value) {
  return value.replace(/\//g, '\\').trim().toLowerCase();
}

function normalizeText(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function reportTextForEntry(reportEntry) {
  return [
    reportEntry?.file,
    ...(reportEntry?.findings ?? []),
    ...(reportEntry?.detections ?? []),
    ...(reportEntry?.evidenceIssueTypes ?? []),
    ...(reportEntry?.proofStatuses ?? []),
  ].map(normalizeText).join(' | ');
}

function matchesExpectedFinding(expectedTitle, reportEntry) {
  const findingTitles = reportEntry?.findings ?? [];
  if (findingTitles.includes(expectedTitle)) {
    return true;
  }

  const expected = normalizeText(expectedTitle);
  const text = reportTextForEntry(reportEntry);
  const file = normalizeFile(reportEntry?.file ?? '');

  if (expected.includes('object level authorization')) {
    return /idor|direct object reference|object level authorization|ownership/.test(text);
  }

  if (expected.includes('function level authorization')) {
    return /missing authorization|broken function level authorization|refund/.test(text);
  }

  if (expected.includes('privilege escalation')) {
    return /privilege|role assignment|role update|missing authorization/.test(text) && file.includes('roles.js');
  }

  if (expected.includes('server side request forgery') || expected.includes('ssrf')) {
    return /ssrf|server side request forgery|untrusted destination/.test(text);
  }

  if (expected.includes('path traversal')) {
    return /path traversal|filesystem path|file read/.test(text);
  }

  if (expected.includes('csrf')) {
    return /csrf|cross site request forgery|state changing/.test(text);
  }

  if (expected.includes('dynamic code evaluation')) {
    return /dynamic code evaluation|code injection|eval|code execution/.test(text);
  }

  if (expected.includes('weak jwt')) {
    return /weak jwt|jwt validation|token validation/.test(text);
  }

  return false;
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
    requiredDetectionChecks: 0,
    requiredDetectionSatisfied: 0,
    primaryScanModesChecked: 0,
    primaryScanModesSatisfied: 0,
    scanTierPostureChecks: 0,
    scanTierPostureSatisfied: 0,
    corroborationPostureChecks: 0,
    corroborationPostureSatisfied: 0,
    proofStatusChecks: 0,
    proofStatusSatisfied: 0,
    proofPromotionChecks: 0,
    proofPromotionSatisfied: 0,
    totalFailures: 0,
  };

  for (const expectation of manifest.expectations) {
    const reportEntry = byFile.get(normalizeFile(expectation.file));
    const findingTitles = reportEntry?.findings ?? [];
    const detections = reportEntry?.detections ?? [];
    const primaryScanMode = reportEntry?.primaryScanMode ?? 'none';
    const scanTierPosture = reportEntry?.scanTierPosture ?? 'none';
    const corroborationPosture = reportEntry?.corroborationPosture ?? 'none';
    const proofPosture = reportEntry?.proofPosture ?? 'none';
    const proofText = [
      ...(reportEntry?.proofStatuses ?? []),
      proofPosture,
    ].map(normalizeText).join(' | ');

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
      if (!matchesExpectedFinding(title, reportEntry)) {
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

    for (const expected of expectation.requiredDetectionIncludes ?? []) {
      metrics.requiredDetectionChecks += 1;
      if (!detections.some(detection => detection.toLowerCase().includes(expected.toLowerCase()))) {
        failures.push(`${expectation.file}: detection summary missing expected fragment ${expected}`);
      } else {
        metrics.requiredDetectionSatisfied += 1;
      }
    }

    if (expectation.requiredPrimaryScanMode) {
      metrics.primaryScanModesChecked += 1;
      if (primaryScanMode !== expectation.requiredPrimaryScanMode) {
        failures.push(`${expectation.file}: expected primary scan mode ${expectation.requiredPrimaryScanMode} but found ${primaryScanMode}`);
      } else {
        metrics.primaryScanModesSatisfied += 1;
      }
    }

    for (const expected of expectation.requiredScanTierPostureIncludes ?? []) {
      metrics.scanTierPostureChecks += 1;
      if (!scanTierPosture.toLowerCase().includes(expected.toLowerCase())) {
        failures.push(`${expectation.file}: scan tier posture missing expected fragment ${expected}`);
      } else {
        metrics.scanTierPostureSatisfied += 1;
      }
    }

    for (const expected of expectation.requiredCorroborationPostureIncludes ?? []) {
      metrics.corroborationPostureChecks += 1;
      if (!corroborationPosture.toLowerCase().includes(expected.toLowerCase())) {
        failures.push(`${expectation.file}: corroboration posture missing expected fragment ${expected}`);
      } else {
        metrics.corroborationPostureSatisfied += 1;
      }
    }

    for (const expected of expectation.requiredProofStatusIncludes ?? []) {
      metrics.proofStatusChecks += 1;
      if (!proofText.includes(normalizeText(expected))) {
        failures.push(`${expectation.file}: proof status missing expected fragment ${expected}`);
      } else {
        metrics.proofStatusSatisfied += 1;
      }
    }

    if (expectation.forbidProofPromotedFindings) {
      metrics.proofPromotionChecks += 1;
      const hasPromotedProof = /\b(static proven|ai plausible)\b/.test(proofText)
        || /static proven:\s*[1-9]/i.test(proofPosture)
        || /ai plausible:\s*[1-9]/i.test(proofPosture);
      if (hasPromotedProof) {
        failures.push(`${expectation.file}: helper-layer finding was proof-promoted`);
      } else {
        metrics.proofPromotionSatisfied += 1;
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
  console.log(`Required detections: ${metrics.requiredDetectionSatisfied}/${metrics.requiredDetectionChecks}`);
  console.log(`Primary scan modes: ${metrics.primaryScanModesSatisfied}/${metrics.primaryScanModesChecked}`);
  console.log(`Scan tier posture checks: ${metrics.scanTierPostureSatisfied}/${metrics.scanTierPostureChecks}`);
  console.log(`Corroboration posture checks: ${metrics.corroborationPostureSatisfied}/${metrics.corroborationPostureChecks}`);
  console.log(`Proof status checks: ${metrics.proofStatusSatisfied}/${metrics.proofStatusChecks}`);
  console.log(`Proof promotion checks: ${metrics.proofPromotionSatisfied}/${metrics.proofPromotionChecks}`);
  console.log(`Total failures: ${metrics.totalFailures}`);
}

const profile = process.argv[2];
const explicitReportPath = process.argv[3];
const jsonMode = process.argv.includes('--json');

if (!profile || !['demo', 'benchmark-app'].includes(profile)) {
  console.error('Usage: node tools/evaluate-stabilization-report.mjs <demo|benchmark-app> [report-path] [--json]');
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
