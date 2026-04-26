import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const evaluatorPath = path.join(repoRoot, 'tools', 'evaluate-stabilization-report.mjs');

function runEval(profile, reportPath) {
  const result = spawnSync(process.execPath, [evaluatorPath, profile, reportPath, '--json'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  const output = result.stdout?.trim() || result.stderr?.trim();
  if (!output) {
    throw new Error(`No evaluator output for ${profile} ${reportPath}`);
  }

  return JSON.parse(output);
}

function loadEval(profile, inputPath) {
  if (/\.json$/i.test(inputPath)) {
    const artifact = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
    if (artifact.profile !== profile) {
      throw new Error(`Expected ${profile} evaluation but found ${artifact.profile} in ${inputPath}`);
    }
    if (!artifact.metrics) {
      throw new Error(`Evaluation artifact has no metrics: ${inputPath}`);
    }
    return artifact;
  }

  return runEval(profile, inputPath);
}

function printDelta(label, baseline, candidate) {
  const diff = candidate - baseline;
  const sign = diff > 0 ? '+' : '';
  console.log(`${label}: ${candidate} (${sign}${diff} vs baseline)`);
}

const [baselineLabel, demoBaseline, benchmarkAppBaseline, candidateLabel, demoCandidate, benchmarkAppCandidate] = process.argv.slice(2);

if (!baselineLabel || !demoBaseline || !benchmarkAppBaseline || !candidateLabel || !demoCandidate || !benchmarkAppCandidate) {
  console.error('Usage: node tools/compare-stabilization-evals.mjs <baseline-label> <demo-report-or-eval-json> <benchmark-app-report-or-eval-json> <candidate-label> <demo-report-or-eval-json> <benchmark-app-report-or-eval-json>');
  process.exit(1);
}

const baselineDemo = loadEval('demo', demoBaseline);
const baselineBenchmarkApp = loadEval('benchmark-app', benchmarkAppBaseline);
const candidateDemo = loadEval('demo', demoCandidate);
const candidateBenchmarkApp = loadEval('benchmark-app', benchmarkAppCandidate);

const baselineFailures = baselineDemo.metrics.totalFailures + baselineBenchmarkApp.metrics.totalFailures;
const candidateFailures = candidateDemo.metrics.totalFailures + candidateBenchmarkApp.metrics.totalFailures;
const baselineClean = baselineDemo.metrics.cleanFilesSatisfied + baselineBenchmarkApp.metrics.cleanFilesSatisfied;
const candidateClean = candidateDemo.metrics.cleanFilesSatisfied + candidateBenchmarkApp.metrics.cleanFilesSatisfied;
const baselineFindings = baselineDemo.metrics.findingFilesSatisfied + baselineBenchmarkApp.metrics.findingFilesSatisfied;
const candidateFindings = candidateDemo.metrics.findingFilesSatisfied + candidateBenchmarkApp.metrics.findingFilesSatisfied;

function sumMetric(metric) {
  return {
    baseline: Number(baselineDemo.metrics[metric] ?? 0) + Number(baselineBenchmarkApp.metrics[metric] ?? 0),
    candidate: Number(candidateDemo.metrics[metric] ?? 0) + Number(candidateBenchmarkApp.metrics[metric] ?? 0),
  };
}

console.log(`Baseline: ${baselineLabel}`);
console.log(`Candidate: ${candidateLabel}`);
console.log('');
printDelta('Total failures', baselineFailures, candidateFailures);
printDelta('Expected finding files satisfied', baselineFindings, candidateFindings);
printDelta('Expected clean files satisfied', baselineClean, candidateClean);
printDelta(
  'Required findings satisfied',
  baselineDemo.metrics.requiredFindingsSatisfied + baselineBenchmarkApp.metrics.requiredFindingsSatisfied,
  candidateDemo.metrics.requiredFindingsSatisfied + candidateBenchmarkApp.metrics.requiredFindingsSatisfied,
);
printDelta(
  'Forbidden findings respected',
  baselineDemo.metrics.forbiddenFindingsSatisfied + baselineBenchmarkApp.metrics.forbiddenFindingsSatisfied,
  candidateDemo.metrics.forbiddenFindingsSatisfied + candidateBenchmarkApp.metrics.forbiddenFindingsSatisfied,
);
printDelta(
  'Required detections satisfied',
  baselineDemo.metrics.requiredDetectionSatisfied + baselineBenchmarkApp.metrics.requiredDetectionSatisfied,
  candidateDemo.metrics.requiredDetectionSatisfied + candidateBenchmarkApp.metrics.requiredDetectionSatisfied,
);
printDelta(
  'Primary scan modes satisfied',
  baselineDemo.metrics.primaryScanModesSatisfied + baselineBenchmarkApp.metrics.primaryScanModesSatisfied,
  candidateDemo.metrics.primaryScanModesSatisfied + candidateBenchmarkApp.metrics.primaryScanModesSatisfied,
);
printDelta(
  'Scan tier posture checks satisfied',
  baselineDemo.metrics.scanTierPostureSatisfied + baselineBenchmarkApp.metrics.scanTierPostureSatisfied,
  candidateDemo.metrics.scanTierPostureSatisfied + candidateBenchmarkApp.metrics.scanTierPostureSatisfied,
);
printDelta(
  'Corroboration posture checks satisfied',
  baselineDemo.metrics.corroborationPostureSatisfied + baselineBenchmarkApp.metrics.corroborationPostureSatisfied,
  candidateDemo.metrics.corroborationPostureSatisfied + candidateBenchmarkApp.metrics.corroborationPostureSatisfied,
);
const probeRun = sumMetric('probeQualityRun');
const probeResolved = sumMetric('probeQualityResolved');
const probeConfirmed = sumMetric('probeQualityConfirmedPaths');
const probeRemoved = sumMetric('probeQualityRemovedOrDowngraded');
const probeManual = sumMetric('probeQualityManualReviewResidue');
const verifierRequested = sumMetric('verifierRequested');
const verifierSkippedHigh = sumMetric('verifierSkippedHighConfidence');
const verifierSkippedLow = sumMetric('verifierSkippedLowSignal');
const skepticRequested = sumMetric('skepticRequested');
const skepticSkippedNoVerifier = sumMetric('skepticSkippedNoVerifier');
const skepticSkippedRejected = sumMetric('skepticSkippedVerifierRejected');
const skepticSkippedStrong = sumMetric('skepticSkippedStrongSupport');
const skepticSkippedStable = sumMetric('skepticSkippedStable');
printDelta('Probe quality resolved', probeResolved.baseline, probeResolved.candidate);
printDelta('Probe quality run', probeRun.baseline, probeRun.candidate);
printDelta('Probe confirmed paths', probeConfirmed.baseline, probeConfirmed.candidate);
printDelta('Probe removed/downgraded candidates', probeRemoved.baseline, probeRemoved.candidate);
printDelta('Probe manual-review residue', probeManual.baseline, probeManual.candidate);
printDelta('Verifier requested', verifierRequested.baseline, verifierRequested.candidate);
printDelta('Verifier skipped high-confidence', verifierSkippedHigh.baseline, verifierSkippedHigh.candidate);
printDelta('Verifier skipped low-signal', verifierSkippedLow.baseline, verifierSkippedLow.candidate);
printDelta('Skeptic requested', skepticRequested.baseline, skepticRequested.candidate);
printDelta('Skeptic skipped no-verifier', skepticSkippedNoVerifier.baseline, skepticSkippedNoVerifier.candidate);
printDelta('Skeptic skipped verifier-rejected', skepticSkippedRejected.baseline, skepticSkippedRejected.candidate);
printDelta('Skeptic skipped strong-support', skepticSkippedStrong.baseline, skepticSkippedStrong.candidate);
printDelta('Skeptic skipped stable', skepticSkippedStable.baseline, skepticSkippedStable.candidate);
console.log('');
console.log(`Demo reports: ${baselineLabel}=${path.resolve(demoBaseline)} | ${candidateLabel}=${path.resolve(demoCandidate)}`);
console.log(`Benchmark-app reports: ${baselineLabel}=${path.resolve(benchmarkAppBaseline)} | ${candidateLabel}=${path.resolve(benchmarkAppCandidate)}`);
