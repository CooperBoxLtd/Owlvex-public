import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot } from './repo-root.mjs';

const latestPath = path.resolve(
  repoRoot,
  'tools/owlvex-benchmark/runs/deterministic/latest.json',
);

function buildStatus(summary) {
  const allSuitesPassing = summary.passedSuites === summary.totalSuites;
  const allCasesPassing = summary.passedCases === summary.totalCases;
  const acceptableForAxis = summary.passed && allSuitesPassing && allCasesPassing;

  return {
    axis: 'execution-risk',
    acceptableForAxis,
    confidence: acceptableForAxis ? 'high-for-covered-axis' : 'not-acceptable',
    releaseStatement: acceptableForAxis
      ? 'The deterministic execution-risk benchmark is passing for all covered suites and cases.'
      : 'The deterministic execution-risk benchmark is not yet acceptable for release on the covered axis.',
    reasons: [
      `gate passed: ${summary.passed}`,
      `suites passing: ${summary.passedSuites}/${summary.totalSuites}`,
      `cases passing: ${summary.passedCases}/${summary.totalCases}`,
      `failed suite: ${summary.failedSuite ?? 'none'}`,
    ],
  };
}

async function main() {
  const raw = await fs.readFile(latestPath, 'utf8');
  const summary = JSON.parse(raw);
  const status = buildStatus(summary);

  console.log(JSON.stringify({
    generatedAt: summary.generatedAt,
    summary,
    status,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
