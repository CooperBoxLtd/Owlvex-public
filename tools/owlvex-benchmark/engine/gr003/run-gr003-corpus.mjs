import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/sanitization_validation');

async function readExpected(expectedPath) {
  return JSON.parse(await fs.readFile(expectedPath, 'utf8'));
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
  const actualTrustState = actual.primaryFinding?.variable === expected.variable
    ? actual.primaryFinding.trustState
    : (actual.states[expected.variable] ?? 'UNKNOWN');
  const actualTransformation = actual.primaryFinding?.variable === expected.variable
    ? actual.primaryFinding.transformation
    : (actual.transformations?.[expected.variable] ?? 'none');

  return {
    variable: expected.variable,
    expectedTrustState: expected.trust_state,
    actualTrustState,
    expectedTransformation: expected.transformation,
    actualTransformation,
    expectedFinding: expected.finding,
    actualFinding: actual.finding,
    passed:
      actualTrustState === expected.trust_state &&
      actualTransformation === expected.transformation &&
      actual.finding === expected.finding,
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
  console.log(JSON.stringify({
    suite: 'gr003-sanitization-validation',
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
