import fs from 'node:fs/promises';
import path from 'node:path';

import { isUnsafeAtSink } from './lattice.mjs';
import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/trust_propagation');

async function readExpected(expectedPath) {
  const raw = await fs.readFile(expectedPath, 'utf8');
  return JSON.parse(raw);
}

async function listCorpusCases() {
  const entries = await fs.readdir(corpusDir);
  return entries
    .filter((name) => name.endsWith('.js'))
    .sort()
    .map((name) => ({
      jsPath: path.join(corpusDir, name),
      expectedPath: path.join(corpusDir, name.replace(/\.js$/, '.expected.json')),
    }));
}

function compareCase(actual, expected) {
  const actualVariable = expected.variable;
  const actualTrustState = actual.primaryFinding?.variable === actualVariable
    ? actual.primaryFinding.trustState
    : (actual.states[actualVariable] ?? 'UNKNOWN');
  const actualUnsafeAtSink = actual.primaryFinding ? isUnsafeAtSink(actual.primaryFinding.trustState) : false;
  const actualFinding = actualUnsafeAtSink;

  return {
    variable: actualVariable,
    sink: actual.primaryFinding?.sink ?? null,
    expectedTrustState: expected.trust_state,
    actualTrustState,
    unsafeAtSink: actualUnsafeAtSink,
    expectedFinding: expected.finding,
    actualFinding,
    passed:
      actualTrustState === expected.trust_state &&
      actualFinding === expected.finding,
  };
}

async function main() {
  const cases = await listCorpusCases();
  const results = [];

  for (const corpusCase of cases) {
    const [expected, actual] = await Promise.all([
      readExpected(corpusCase.expectedPath),
      evaluateFile(corpusCase.jsPath),
    ]);

    results.push({
      file: path.basename(corpusCase.jsPath),
      ...compareCase(actual, expected),
    });
  }

  const passed = results.filter((result) => result.passed).length;
  const summary = {
    suite: 'gr002-trust-propagation',
    passed,
    total: results.length,
    results,
  };

  console.log(JSON.stringify(summary, null, 2));

  if (passed !== results.length) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
