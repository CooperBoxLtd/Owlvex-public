import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/sql_query');
const cases = [
  'propagation_unsafe_query_positive.js',
  'propagation_safe_query_negative.js',
  'propagation_mixed_query_edge.js',
];

async function readExpected(expectedPath) {
  return JSON.parse(await fs.readFile(expectedPath, 'utf8'));
}

async function listCorpusCases() {
  return cases.map((name) => ({
    jsPath: path.join(corpusDir, name),
    expectedPath: path.join(corpusDir, name.replace(/\.js$/, '.expected.json')),
  }));
}

async function main() {
  const corpusCases = await listCorpusCases();
  const results = [];

  for (const corpusCase of corpusCases) {
    const [expected, actual] = await Promise.all([
      readExpected(corpusCase.expectedPath),
      evaluateFile(corpusCase.jsPath),
    ]);

    results.push({
      file: path.basename(corpusCase.jsPath),
      expectedTrustState: expected.trust_state,
      actualTrustState: actual.trustStateAtSink,
      expectedFinding: expected.finding,
      actualFinding: actual.parameterized ? false : actual.trustStateAtSink !== 'SAFE',
      passed:
        actual.trustStateAtSink === expected.trust_state
        && (actual.parameterized ? false : actual.trustStateAtSink !== 'SAFE') === expected.finding,
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'sq002-query-trust-propagation',
    passed,
    total: results.length,
    results,
  }, null, 2));

  if (passed !== results.length) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
