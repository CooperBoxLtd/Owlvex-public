import fs from 'node:fs/promises';
import path from 'node:path';

import { repoRoot } from './repo-root.mjs';

const benchmarkRoots = [
  {
    name: 'deterministic-axis',
    kind: 'aggregate',
    dir: path.resolve(repoRoot, 'tools/owlvex-benchmark/runs/deterministic'),
  },
  {
    name: 'engine-proof-contracts',
    kind: 'proof-contract',
    dir: path.resolve(repoRoot, 'tools/owlvex-benchmark/runs/proof-contracts'),
  },
];

function pct(numerator, denominator) {
  if (!denominator) {
    return null;
  }
  return Number(((numerator / denominator) * 100).toFixed(2));
}

function delta(current, previous) {
  if (current === null || previous === null || current === undefined || previous === undefined) {
    return null;
  }
  return Number((current - previous).toFixed(2));
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function listRunFiles(dir) {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .filter((name) => name.endsWith('.json') && name !== 'latest.json' && !name.endsWith('.full.json'))
      .sort();
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

async function previousRunPath(dir) {
  const files = await listRunFiles(dir);
  if (files.length < 2) {
    return null;
  }
  return path.join(dir, files[files.length - 2]);
}

function summarizeDeterministic(run) {
  return {
    generatedAt: run.generatedAt ?? null,
    passed: Boolean(run.passed),
    totalSuites: run.totalSuites ?? run.total ?? null,
    passedSuites: run.passedSuites ?? (run.results ?? []).filter((entry) => entry.passed).length,
    totalCases: run.totalCases ?? (run.results ?? []).reduce((total, entry) => total + (entry.casesTotal ?? entry.summary?.total ?? 0), 0),
    passedCases: run.passedCases ?? (run.results ?? []).reduce((total, entry) => total + (entry.casesPassed ?? entry.summary?.passed ?? 0), 0),
  };
}

function summarizeProofContracts(run) {
  const results = run.results ?? [];
  const unsafeCases = results.filter((entry) => (entry.expectedCanonicalIds ?? []).length > 0);
  const safeCases = results.filter((entry) => (entry.expectedCanonicalIds ?? []).length === 0);
  const evidenceCases = results.filter((entry) => (entry.expectedEvidenceTypes ?? []).length > 0);

  return {
    generatedAt: run.generatedAt ?? null,
    passed: run.passed === run.total,
    totalCases: run.total ?? results.length,
    passedCases: run.passed ?? results.filter((entry) => entry.passed).length,
    unsafeCases: unsafeCases.length,
    unsafeCasesPassed: unsafeCases.filter((entry) => entry.passed).length,
    safeCases: safeCases.length,
    safeCasesPassed: safeCases.filter((entry) => entry.passed).length,
    evidenceCases: evidenceCases.length,
    evidenceShapePassed: evidenceCases.filter((entry) => entry.evidenceShapePass).length,
  };
}

function withRates(summary, kind) {
  if (kind === 'aggregate') {
    return {
      ...summary,
      suitePassRate: pct(summary.passedSuites, summary.totalSuites),
      casePassRate: pct(summary.passedCases, summary.totalCases),
    };
  }

  return {
    ...summary,
    casePassRate: pct(summary.passedCases, summary.totalCases),
    unsafeRecallRate: pct(summary.unsafeCasesPassed, summary.unsafeCases),
    safeQuietRate: pct(summary.safeCasesPassed, summary.safeCases),
    evidenceShapeRate: pct(summary.evidenceShapePassed, summary.evidenceCases),
  };
}

function compare(current, previous, kind) {
  if (!previous) {
    return {
      baseline: 'none',
      direction: 'no-prior-run',
      deltas: {},
    };
  }

  const deltas = kind === 'aggregate'
    ? {
        suitePassRate: delta(current.suitePassRate, previous.suitePassRate),
        casePassRate: delta(current.casePassRate, previous.casePassRate),
        totalCases: delta(current.totalCases, previous.totalCases),
      }
    : {
        casePassRate: delta(current.casePassRate, previous.casePassRate),
        unsafeRecallRate: delta(current.unsafeRecallRate, previous.unsafeRecallRate),
        safeQuietRate: delta(current.safeQuietRate, previous.safeQuietRate),
        evidenceShapeRate: delta(current.evidenceShapeRate, previous.evidenceShapeRate),
        totalCases: delta(current.totalCases, previous.totalCases),
      };

  const numericDeltas = Object.values(deltas).filter((value) => typeof value === 'number');
  const anyNegative = numericDeltas.some((value) => value < 0);
  const anyPositive = numericDeltas.some((value) => value > 0);

  return {
    baseline: previous.generatedAt ?? 'previous-run',
    direction: anyNegative ? 'regressed' : anyPositive ? 'improved-or-expanded' : 'unchanged',
    deltas,
  };
}

async function summarizeRoot(root) {
  const latestPath = path.join(root.dir, 'latest.json');
  let latest;
  try {
    latest = await readJson(latestPath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        name: root.name,
        kind: root.kind,
        available: false,
        reason: 'No latest benchmark artifact exists. Run the benchmark first.',
      };
    }
    throw error;
  }

  const previousPath = await previousRunPath(root.dir);
  const previous = previousPath ? await readJson(previousPath) : null;
  const summarize = root.kind === 'aggregate' ? summarizeDeterministic : summarizeProofContracts;
  const currentMetrics = withRates(summarize(latest), root.kind);
  const previousMetrics = previous ? withRates(summarize(previous), root.kind) : null;

  return {
    name: root.name,
    kind: root.kind,
    available: true,
    latestPath,
    previousPath,
    current: currentMetrics,
    previous: previousMetrics,
    trend: compare(currentMetrics, previousMetrics, root.kind),
  };
}

async function main() {
  const benchmarks = [];
  for (const root of benchmarkRoots) {
    benchmarks.push(await summarizeRoot(root));
  }

  console.log(JSON.stringify({
    generatedAt: new Date().toISOString(),
    benchmarks,
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
