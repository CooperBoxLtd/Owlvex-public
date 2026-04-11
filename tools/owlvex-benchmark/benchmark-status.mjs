import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot } from './repo-root.mjs';

const latestPath = path.resolve(
  repoRoot,
  'tools/owlvex-benchmark/runs/deterministic/latest.json',
);

const AXIS_SUITES = {
  'execution-risk': ['gr002', 'gr003', 'gr004', 'gr005', 'gr001', 'integration'],
  'sql-query': ['sq002', 'sq003', 'sq004', 'sq005', 'sq001', 'sql-integration'],
  'access-control': ['ac002', 'ac004', 'ac003', 'ac005', 'ac001', 'ac-integration'],
  'conditional-rules': ['sm002'],
};

function buildAxisStatus(axisName, suiteNames, results) {
  const axisResults = results.filter((entry) => suiteNames.includes(entry.name));
  const allPassing = axisResults.every((entry) => entry.passed);
  const passedSuites = axisResults.filter((entry) => entry.passed).length;
  const totalCases = axisResults.reduce((n, entry) => n + (entry.casesTotal ?? 0), 0);
  const passedCases = axisResults.reduce((n, entry) => n + (entry.casesPassed ?? 0), 0);
  const failedSuite = axisResults.find((entry) => !entry.passed)?.name ?? null;

  return {
    axis: axisName,
    acceptableForAxis: allPassing,
    confidence: allPassing ? 'high-for-covered-axis' : 'not-acceptable',
    releaseStatement: allPassing
      ? `The deterministic ${axisName} benchmark is passing for all covered suites and cases.`
      : `The deterministic ${axisName} benchmark is not yet acceptable for release on the covered axis.`,
    reasons: [
      `suites passing: ${passedSuites}/${suiteNames.length}`,
      `cases passing: ${passedCases}/${totalCases}`,
      `failed suite: ${failedSuite ?? 'none'}`,
    ],
  };
}

function buildStatus(summary) {
  const allSuitesPassing = summary.passedSuites === summary.totalSuites;
  const allCasesPassing = summary.passedCases === summary.totalCases;
  const acceptableForAxis = summary.passed && allSuitesPassing && allCasesPassing;
  const results = summary.results ?? [];

  const axes = Object.entries(AXIS_SUITES).map(([axisName, suiteNames]) =>
    buildAxisStatus(axisName, suiteNames, results),
  );

  return {
    overall: {
      acceptableForRelease: acceptableForAxis,
      confidence: acceptableForAxis ? 'high-for-all-axes' : 'not-acceptable',
      releaseStatement: acceptableForAxis
        ? 'All deterministic axes are passing. Product is acceptable for the covered behaviors.'
        : 'One or more deterministic axes are failing. Review individual axis status.',
      reasons: [
        `gate passed: ${summary.passed}`,
        `suites passing: ${summary.passedSuites}/${summary.totalSuites}`,
        `cases passing: ${summary.passedCases}/${summary.totalCases}`,
        `failed suite: ${summary.failedSuite ?? 'none'}`,
      ],
    },
    axes,
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
