import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

function normalizeFile(value) {
  return String(value ?? '').replace(/\//g, '\\').trim().toLowerCase();
}

function defaultResultsPath(repoRoot) {
  return path.join(repoRoot, 'tools', 'fix-benchmark', 'fix-benchmark.results.template.json');
}

function percentage(numerator, denominator) {
  if (!denominator) {
    return 0;
  }
  return Number(((numerator / denominator) * 100).toFixed(1));
}

function evaluateFixBenchmark(manifest, results) {
  const runsByCaseId = new Map((results.runs ?? []).map(entry => [entry.caseId, entry]));
  const details = [];

  let totalCases = 0;
  let attemptedCases = 0;
  let previewChecks = 0;
  let previewsGenerated = 0;
  let scopeChecks = 0;
  let scopeKept = 0;
  let applyChecks = 0;
  let cleanApplies = 0;
  let syntaxChecks = 0;
  let syntaxValid = 0;
  let removalChecks = 0;
  let findingsRemoved = 0;
  let noNewRiskChecks = 0;
  let noNewRiskPasses = 0;

  for (const expectation of manifest.expectations ?? []) {
    totalCases += 1;
    const run = runsByCaseId.get(expectation.caseId);
    const attempted = Boolean(run?.attempted);
    if (attempted) {
      attemptedCases += 1;
    }

    const normalizedExpectedFile = normalizeFile(expectation.file);
    const changedFiles = Array.isArray(run?.filesChanged) ? run.filesChanged.map(normalizeFile) : [];
    const expectedScope = expectation.expectedFixProperties?.scope ?? 'same_file';
    const sameFileScope = changedFiles.every(file => file === normalizedExpectedFile);
    const scopePassed = !attempted
      ? false
      : expectedScope === 'same_file'
        ? changedFiles.length > 0 && sameFileScope
        : changedFiles.length > 0;

    if (expectation.expectedFixProperties?.previewRequired) {
      previewChecks += 1;
      if (run?.previewGenerated === true) {
        previewsGenerated += 1;
      }
    }

    scopeChecks += 1;
    if (scopePassed) {
      scopeKept += 1;
    }

    applyChecks += 1;
    if (run?.appliedCleanly === true) {
      cleanApplies += 1;
    }

    if (typeof run?.syntaxValid === 'boolean') {
      syntaxChecks += 1;
      if (run.syntaxValid) {
        syntaxValid += 1;
      }
    }

    if (typeof run?.targetFindingRemoved === 'boolean') {
      removalChecks += 1;
      if (run.targetFindingRemoved) {
        findingsRemoved += 1;
      }
    }

    if (typeof run?.introducedHighRiskFindings === 'boolean') {
      noNewRiskChecks += 1;
      if (!run.introducedHighRiskFindings) {
        noNewRiskPasses += 1;
      }
    }

    details.push({
      caseId: expectation.caseId,
      file: expectation.file,
      scenario: expectation.scenario,
      attempted,
      previewGenerated: run?.previewGenerated ?? false,
      appliedCleanly: run?.appliedCleanly ?? false,
      scopePassed,
      syntaxValid: run?.syntaxValid ?? null,
      targetFindingRemoved: run?.targetFindingRemoved ?? null,
      noNewHighRiskFindings: typeof run?.introducedHighRiskFindings === 'boolean'
        ? !run.introducedHighRiskFindings
        : null,
      filesChanged: run?.filesChanged ?? [],
      notes: run?.notes ?? '',
    });
  }

  const metrics = {
    attemptRate: percentage(attemptedCases, totalCases),
    previewRate: percentage(previewsGenerated, previewChecks),
    scopeDisciplineRate: percentage(scopeKept, scopeChecks),
    cleanApplyRate: percentage(cleanApplies, applyChecks),
    syntaxValidityRate: percentage(syntaxValid, syntaxChecks),
    findingRemovalRate: percentage(findingsRemoved, removalChecks),
    noNewHighRiskRate: percentage(noNewRiskPasses, noNewRiskChecks),
  };

  const overallScore = Number((
    metrics.previewRate * 0.15
    + metrics.scopeDisciplineRate * 0.2
    + metrics.cleanApplyRate * 0.15
    + metrics.syntaxValidityRate * 0.15
    + metrics.findingRemovalRate * 0.25
    + metrics.noNewHighRiskRate * 0.1
  ).toFixed(1));

  return {
    overallScore,
    metrics,
    counts: {
      totalCases,
      attemptedCases,
      previewChecks,
      previewsGenerated,
      scopeChecks,
      scopeKept,
      applyChecks,
      cleanApplies,
      syntaxChecks,
      syntaxValid,
      removalChecks,
      findingsRemoved,
      noNewRiskChecks,
      noNewRiskPasses,
    },
    details,
  };
}

function printSummary(result, resultsPath) {
  console.log(`Fix benchmark results: ${resultsPath}`);
  console.log(`Overall fix quality score: ${result.overallScore}/100`);
  console.log(`Attempt rate: ${result.metrics.attemptRate}% (${result.counts.attemptedCases}/${result.counts.totalCases})`);
  console.log(`Preview generation rate: ${result.metrics.previewRate}% (${result.counts.previewsGenerated}/${result.counts.previewChecks})`);
  console.log(`Scope discipline rate: ${result.metrics.scopeDisciplineRate}% (${result.counts.scopeKept}/${result.counts.scopeChecks})`);
  console.log(`Clean apply rate: ${result.metrics.cleanApplyRate}% (${result.counts.cleanApplies}/${result.counts.applyChecks})`);
  console.log(`Syntax validity rate: ${result.metrics.syntaxValidityRate}% (${result.counts.syntaxValid}/${result.counts.syntaxChecks})`);
  console.log(`Finding removal rate: ${result.metrics.findingRemovalRate}% (${result.counts.findingsRemoved}/${result.counts.removalChecks})`);
  console.log(`No-new-high-risk rate: ${result.metrics.noNewHighRiskRate}% (${result.counts.noNewRiskPasses}/${result.counts.noNewRiskChecks})`);
  console.log('');
  console.log('Per-case outcomes:');
  for (const detail of result.details) {
    console.log(`- ${detail.caseId} | attempted=${detail.attempted} | preview=${detail.previewGenerated} | scope=${detail.scopePassed} | apply=${detail.appliedCleanly} | syntax=${detail.syntaxValid} | removed=${detail.targetFindingRemoved} | noNewHighRisk=${detail.noNewHighRiskFindings}`);
  }
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = path.join(repoRoot, 'tools', 'fix-benchmark', 'fix-benchmark.expectations.json');
const explicitResultsPath = process.argv[2] && process.argv[2] !== '--json'
  ? path.resolve(process.argv[2])
  : defaultResultsPath(repoRoot);
const jsonMode = process.argv.includes('--json');

if (!fs.existsSync(explicitResultsPath)) {
  console.error('No fix benchmark results file found. Pass a results JSON path or use the starter template under tools/fix-benchmark/.');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const results = JSON.parse(fs.readFileSync(explicitResultsPath, 'utf8'));
const evaluation = evaluateFixBenchmark(manifest, results);

if (jsonMode) {
  console.log(JSON.stringify({
    resultsPath: explicitResultsPath,
    benchmark: manifest.name,
    ...evaluation,
  }, null, 2));
} else {
  printSummary(evaluation, explicitResultsPath);
}
