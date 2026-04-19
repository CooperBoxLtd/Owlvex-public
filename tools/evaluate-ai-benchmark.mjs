import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

function normalizeFile(value) {
  return value.replace(/\//g, '\\').trim().toLowerCase();
}

function latestReportPath(dir) {
  return fs.readdirSync(dir)
    .filter(name => /^owlvex-scan-report-\d{8}-\d{6}\.md$/i.test(name))
    .sort()
    .at(-1);
}

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
    let primaryScanMode;
    let evidence;
    let detectionConfidence;

    for (let inner = index + 1; inner < lines.length; inner += 1) {
      const line = lines[inner];
      if (/^###\s+/.test(line)) {
        break;
      }

      const primaryScanModeMatch = line.match(/^-\s+(?:Primary scan mode|Analysis mode):\s+(.+)$/);
      if (primaryScanModeMatch && !primaryScanMode) {
        primaryScanMode = primaryScanModeMatch[1].trim();
      }

      const evidenceMatch = line.match(/^-\s+(?:Corroboration posture|Evidence):\s+(.+)$/);
      if (evidenceMatch && !evidence) {
        evidence = evidenceMatch[1].trim();
      }

      const confidenceMatch = line.match(/^-\s+Detection confidence:\s+(\d+)%$/);
      if (confidenceMatch && detectionConfidence === undefined) {
        detectionConfidence = Number(confidenceMatch[1]);
      }

      const tableMatch = line.match(/^\|\s*(.+?)\s*\|\s*.+\|\s*(.+?)\s*\|$/);
      if (tableMatch && tableMatch[1] !== 'Finding' && tableMatch[1] !== '---') {
        findings.push({
          title: tableMatch[1].trim(),
          detection: tableMatch[2].trim(),
        });
      }
    }

    files.push({
      file,
      findings,
      primaryScanMode,
      evidence,
      detectionConfidence,
    });
  }

  return { files };
}

function percentage(numerator, denominator) {
  if (!denominator) {
    return 0;
  }
  return Number(((numerator / denominator) * 100).toFixed(1));
}

function average(values) {
  if (!values.length) {
    return 0;
  }
  return Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(1));
}

function evaluateAiBenchmark(report, manifest) {
  const byFile = new Map(report.files.map(entry => [normalizeFile(entry.file), entry]));
  const details = [];

  let unsafeTotal = 0;
  let unsafeDetected = 0;
  let safeTotal = 0;
  let safeQuiet = 0;
  let familyChecks = 0;
  let familyMatches = 0;
  let recommendedAgentChecks = 0;
  let recommendedAgentMatches = 0;
  const unsafeConfidenceScores = [];

  for (const expectation of manifest.expectations) {
    const reportEntry = byFile.get(normalizeFile(expectation.file));
    const findings = reportEntry?.findings ?? [];
    const titles = findings.map(finding => finding.title.toLowerCase());
    const mode = reportEntry?.primaryScanMode ?? 'none';
    const hasFinding = findings.length > 0;
    const expectedFragments = (expectation.expectedFindingAnyOfIncludes ?? []).map(fragment => fragment.toLowerCase());
    const familyMatched = !expectedFragments.length || expectedFragments.some(fragment =>
      titles.some(title => title.includes(fragment)),
    );

    if (expectation.track === 'unsafe') {
      unsafeTotal += 1;
      if (hasFinding) {
        unsafeDetected += 1;
        if (typeof reportEntry?.detectionConfidence === 'number') {
          unsafeConfidenceScores.push(reportEntry.detectionConfidence);
        }
      }
      familyChecks += 1;
      if (hasFinding && familyMatched) {
        familyMatches += 1;
      }
    } else if (expectation.track === 'safe') {
      safeTotal += 1;
      if (!hasFinding) {
        safeQuiet += 1;
      }
    }

    if (expectation.recommendedAgent) {
      recommendedAgentChecks += 1;
      const expectedMode =
        expectation.recommendedAgent === 'TARGETED_AI'
          ? 'Targeted AI review'
          : expectation.recommendedAgent === 'REPO_AI'
            ? 'Repo-context AI review'
            : expectation.recommendedAgent;
      if (mode === expectedMode || (!hasFinding && expectation.track === 'safe')) {
        recommendedAgentMatches += 1;
      }
    }

    details.push({
      file: expectation.file,
      scenario: expectation.scenario,
      recommendedAgent: expectation.recommendedAgent,
      expectedState: expectation.expectedState,
      actualState: hasFinding ? 'finding' : 'clean',
      primaryScanMode: mode,
      evidence: reportEntry?.evidence ?? 'none',
      matchedFindingTitles: findings.map(finding => finding.title),
      familyMatched,
      detectionConfidence: reportEntry?.detectionConfidence ?? null,
    });
  }

  const metrics = {
    unsafeRecall: percentage(unsafeDetected, unsafeTotal),
    safeQuietRate: percentage(safeQuiet, safeTotal),
    familyMatchRate: percentage(familyMatches, familyChecks),
    recommendedAgentFitRate: percentage(recommendedAgentMatches, recommendedAgentChecks),
    averageUnsafeDetectionConfidence: average(unsafeConfidenceScores),
  };

  const overallScore = Number((
    (metrics.unsafeRecall * 0.4)
    + (metrics.safeQuietRate * 0.3)
    + (metrics.familyMatchRate * 0.2)
    + (metrics.recommendedAgentFitRate * 0.1)
  ).toFixed(1));

  return {
    passed: metrics.unsafeRecall === 100 && metrics.safeQuietRate === 100,
    overallScore,
    metrics,
    counts: {
      unsafeTotal,
      unsafeDetected,
      safeTotal,
      safeQuiet,
      familyChecks,
      familyMatches,
      recommendedAgentChecks,
      recommendedAgentMatches,
    },
    details,
  };
}

function printSummary(result, reportPath) {
  console.log(`AI benchmark report: ${reportPath}`);
  console.log(`Overall AI quality score: ${result.overallScore}/100`);
  console.log(`Unsafe recall: ${result.metrics.unsafeRecall}% (${result.counts.unsafeDetected}/${result.counts.unsafeTotal})`);
  console.log(`Safe quiet rate: ${result.metrics.safeQuietRate}% (${result.counts.safeQuiet}/${result.counts.safeTotal})`);
  console.log(`Issue-family match rate: ${result.metrics.familyMatchRate}% (${result.counts.familyMatches}/${result.counts.familyChecks})`);
  console.log(`Recommended-agent fit rate: ${result.metrics.recommendedAgentFitRate}% (${result.counts.recommendedAgentMatches}/${result.counts.recommendedAgentChecks})`);
  console.log(`Average unsafe detection confidence: ${result.metrics.averageUnsafeDetectionConfidence}%`);
  console.log('');
  console.log('Per-file outcomes:');
  for (const detail of result.details) {
    const outcome = `${detail.file}: expected ${detail.expectedState}, got ${detail.actualState}`;
    const family = detail.familyMatched ? 'family ok' : 'family drift';
    const agent = detail.recommendedAgent ? `recommended ${detail.recommendedAgent} -> ${detail.primaryScanMode}` : detail.primaryScanMode;
    console.log(`- ${outcome} | ${family} | ${agent}`);
  }
}

const explicitReportPath = process.argv[2] && process.argv[2] !== '--json'
  ? path.resolve(process.argv[2])
  : null;
const jsonMode = process.argv.includes('--json');

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const targetDir = path.join(repoRoot, 'tools', 'demo');
const manifestPath = path.join(targetDir, 'ai-benchmark.expectations.json');
const reportPath = explicitReportPath ?? path.join(targetDir, latestReportPath(targetDir) ?? '');

if (!fs.existsSync(reportPath)) {
  console.error('No AI benchmark report found. Provide a report path explicitly or generate a fresh demo report first.');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const markdown = fs.readFileSync(reportPath, 'utf8');
const report = parseMarkdownReport(markdown);
const evaluation = evaluateAiBenchmark(report, manifest);

if (jsonMode) {
  console.log(JSON.stringify({
    reportPath,
    benchmark: manifest.name,
    ...evaluation,
  }, null, 2));
} else {
  printSummary(evaluation, reportPath);
}
