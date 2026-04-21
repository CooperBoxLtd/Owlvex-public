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

function buildArtifactFreshness(generatedAt) {
  const generatedAtMs = Date.parse(generatedAt);
  if (Number.isNaN(generatedAtMs)) {
    return {
      ageMs: null,
      freshness: 'unknown',
      freshnessNote: 'Artifact timestamp could not be parsed.',
    };
  }

  const ageMs = Math.max(0, Date.now() - generatedAtMs);
  const ageHours = ageMs / (1000 * 60 * 60);

  if (ageHours < 24) {
    return {
      ageMs,
      freshness: 'fresh',
      freshnessNote: 'Artifact is less than 24 hours old.',
    };
  }

  if (ageHours < 24 * 7) {
    return {
      ageMs,
      freshness: 'stale',
      freshnessNote: 'Artifact is older than 24 hours. Re-run the deterministic gate before using it as a current signal.',
    };
  }

  return {
    ageMs,
    freshness: 'very-stale',
    freshnessNote: 'Artifact is older than 7 days. Treat it as historical benchmark evidence, not current checkout status.',
  };
}

function buildAxisStatus(axisName, suiteNames, results) {
  const axisResults = results.filter((entry) => suiteNames.includes(entry.name));
  const allPassing = axisResults.every((entry) => entry.passed);
  const passedSuites = axisResults.filter((entry) => entry.passed).length;
  const totalCases = axisResults.reduce((n, entry) => n + (entry.casesTotal ?? 0), 0);
  const passedCases = axisResults.reduce((n, entry) => n + (entry.casesPassed ?? 0), 0);
  const failedSuite = axisResults.find((entry) => !entry.passed)?.name ?? null;

  return {
    axis: axisName,
    artifactPassing: allPassing,
    confidence: allPassing ? 'high-for-covered-axis' : 'not-acceptable',
    statusStatement: allPassing
      ? `The latest recorded deterministic ${axisName} benchmark artifact is passing for all covered suites and cases.`
      : `The latest recorded deterministic ${axisName} benchmark artifact is not passing for the covered axis.`,
    reasons: [
      `suites passing: ${passedSuites}/${suiteNames.length}`,
      `cases passing: ${passedCases}/${totalCases}`,
      `failed suite: ${failedSuite ?? 'none'}`,
    ],
    limitations: [
      'This is artifact-backed benchmark status only.',
      'This does not confirm current checkout health outside the covered deterministic suites.',
    ],
  };
}

function buildStatus(summary) {
  const allSuitesPassing = summary.passedSuites === summary.totalSuites;
  const allCasesPassing = summary.passedCases === summary.totalCases;
  const artifactPassing = summary.passed && allSuitesPassing && allCasesPassing;
  const results = summary.results ?? [];

  const axes = Object.entries(AXIS_SUITES).map(([axisName, suiteNames]) =>
    buildAxisStatus(axisName, suiteNames, results),
  );

  return {
    overall: {
      artifactPassing,
      releaseReadiness: 'unknown',
      checkoutHealth: 'unknown',
      confidence: artifactPassing ? 'high-for-covered-deterministic-artifact' : 'not-acceptable',
      statusStatement: artifactPassing
        ? 'All deterministic axes are passing in the latest recorded benchmark artifact.'
        : 'One or more deterministic axes are failing in the latest recorded benchmark artifact.',
      reasons: [
        `gate passed: ${summary.passed}`,
        `suites passing: ${summary.passedSuites}/${summary.totalSuites}`,
        `cases passing: ${summary.passedCases}/${summary.totalCases}`,
        `failed suite: ${summary.failedSuite ?? 'none'}`,
      ],
      limitations: [
        'This command reads the latest recorded deterministic benchmark artifact.',
        'It does not run benchmarks, unit tests, or backend tests for the current checkout.',
        'Do not treat this output alone as a release decision.',
      ],
    },
    axes,
  };
}

async function main() {
  const raw = await fs.readFile(latestPath, 'utf8');
  const summary = JSON.parse(raw);
  const status = buildStatus(summary);
  const artifact = {
    source: 'latest-recorded-deterministic-run',
    path: latestPath,
    generatedAt: summary.generatedAt,
    ...buildArtifactFreshness(summary.generatedAt),
  };

  console.log(JSON.stringify({
    artifact,
    summary,
    status,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
