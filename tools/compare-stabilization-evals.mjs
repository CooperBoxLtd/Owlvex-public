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

const [baselineLabel, demoBaseline, demoAppBaseline, candidateLabel, demoCandidate, demoAppCandidate] = process.argv.slice(2);

if (!baselineLabel || !demoBaseline || !demoAppBaseline || !candidateLabel || !demoCandidate || !demoAppCandidate) {
  console.error('Usage: node tools/compare-stabilization-evals.mjs <baseline-label> <demo-report> <demo-app-report> <candidate-label> <demo-report> <demo-app-report>');
  process.exit(1);
}

const baselineDemo = runEval('demo', demoBaseline);
const baselineDemoApp = runEval('demo-app', demoAppBaseline);
const candidateDemo = runEval('demo', demoCandidate);
const candidateDemoApp = runEval('demo-app', demoAppCandidate);

const baselineFailures = baselineDemo.metrics.totalFailures + baselineDemoApp.metrics.totalFailures;
const candidateFailures = candidateDemo.metrics.totalFailures + candidateDemoApp.metrics.totalFailures;
const baselineClean = baselineDemo.metrics.cleanFilesSatisfied + baselineDemoApp.metrics.cleanFilesSatisfied;
const candidateClean = candidateDemo.metrics.cleanFilesSatisfied + candidateDemoApp.metrics.cleanFilesSatisfied;
const baselineFindings = baselineDemo.metrics.findingFilesSatisfied + baselineDemoApp.metrics.findingFilesSatisfied;
const candidateFindings = candidateDemo.metrics.findingFilesSatisfied + candidateDemoApp.metrics.findingFilesSatisfied;

console.log(`Baseline: ${baselineLabel}`);
console.log(`Candidate: ${candidateLabel}`);
console.log('');
printDelta('Total failures', baselineFailures, candidateFailures);
printDelta('Expected finding files satisfied', baselineFindings, candidateFindings);
printDelta('Expected clean files satisfied', baselineClean, candidateClean);
printDelta(
  'Required findings satisfied',
  baselineDemo.metrics.requiredFindingsSatisfied + baselineDemoApp.metrics.requiredFindingsSatisfied,
  candidateDemo.metrics.requiredFindingsSatisfied + candidateDemoApp.metrics.requiredFindingsSatisfied,
);
printDelta(
  'Forbidden findings respected',
  baselineDemo.metrics.forbiddenFindingsSatisfied + baselineDemoApp.metrics.forbiddenFindingsSatisfied,
  candidateDemo.metrics.forbiddenFindingsSatisfied + candidateDemoApp.metrics.forbiddenFindingsSatisfied,
);
printDelta(
  'Required detections satisfied',
  baselineDemo.metrics.requiredDetectionSatisfied + baselineDemoApp.metrics.requiredDetectionSatisfied,
  candidateDemo.metrics.requiredDetectionSatisfied + candidateDemoApp.metrics.requiredDetectionSatisfied,
);
printDelta(
  'Primary scan modes satisfied',
  baselineDemo.metrics.primaryScanModesSatisfied + baselineDemoApp.metrics.primaryScanModesSatisfied,
  candidateDemo.metrics.primaryScanModesSatisfied + candidateDemoApp.metrics.primaryScanModesSatisfied,
);
printDelta(
  'Scan tier posture checks satisfied',
  baselineDemo.metrics.scanTierPostureSatisfied + baselineDemoApp.metrics.scanTierPostureSatisfied,
  candidateDemo.metrics.scanTierPostureSatisfied + candidateDemoApp.metrics.scanTierPostureSatisfied,
);
printDelta(
  'Corroboration posture checks satisfied',
  baselineDemo.metrics.corroborationPostureSatisfied + baselineDemoApp.metrics.corroborationPostureSatisfied,
  candidateDemo.metrics.corroborationPostureSatisfied + candidateDemoApp.metrics.corroborationPostureSatisfied,
);
console.log('');
console.log(`Demo reports: ${baselineLabel}=${path.resolve(demoBaseline)} | ${candidateLabel}=${path.resolve(demoCandidate)}`);
console.log(`Demo-app reports: ${baselineLabel}=${path.resolve(demoAppBaseline)} | ${candidateLabel}=${path.resolve(demoAppCandidate)}`);
