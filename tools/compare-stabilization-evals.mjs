import { spawnSync } from 'child_process';
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

function printDelta(label, baseline, candidate) {
  const diff = candidate - baseline;
  const sign = diff > 0 ? '+' : '';
  console.log(`${label}: ${candidate} (${sign}${diff} vs baseline)`);
}

const [baselineLabel, demoBaseline, benchmarkAppBaseline, candidateLabel, demoCandidate, benchmarkAppCandidate] = process.argv.slice(2);

if (!baselineLabel || !demoBaseline || !benchmarkAppBaseline || !candidateLabel || !demoCandidate || !benchmarkAppCandidate) {
  console.error('Usage: node tools/compare-stabilization-evals.mjs <baseline-label> <demo-report> <benchmark-app-report> <candidate-label> <demo-report> <benchmark-app-report>');
  process.exit(1);
}

const baselineDemo = runEval('demo', demoBaseline);
const baselineBenchmarkApp = runEval('benchmark-app', benchmarkAppBaseline);
const candidateDemo = runEval('demo', demoCandidate);
const candidateBenchmarkApp = runEval('benchmark-app', benchmarkAppCandidate);

const baselineFailures = baselineDemo.metrics.totalFailures + baselineBenchmarkApp.metrics.totalFailures;
const candidateFailures = candidateDemo.metrics.totalFailures + candidateBenchmarkApp.metrics.totalFailures;
const baselineClean = baselineDemo.metrics.cleanFilesSatisfied + baselineBenchmarkApp.metrics.cleanFilesSatisfied;
const candidateClean = candidateDemo.metrics.cleanFilesSatisfied + candidateBenchmarkApp.metrics.cleanFilesSatisfied;
const baselineFindings = baselineDemo.metrics.findingFilesSatisfied + baselineBenchmarkApp.metrics.findingFilesSatisfied;
const candidateFindings = candidateDemo.metrics.findingFilesSatisfied + candidateBenchmarkApp.metrics.findingFilesSatisfied;

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
console.log('');
console.log(`Demo reports: ${baselineLabel}=${path.resolve(demoBaseline)} | ${candidateLabel}=${path.resolve(demoCandidate)}`);
console.log(`Benchmark-app reports: ${baselineLabel}=${path.resolve(benchmarkAppBaseline)} | ${candidateLabel}=${path.resolve(benchmarkAppCandidate)}`);
