import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/access_control_context');
const cases = [
  'arbitrary_missing_positive.js',
  'arbitrary_explicit_negative.js',
];

async function readExpected(expectedPath) {
  return JSON.parse(await fs.readFile(expectedPath, 'utf8'));
}

async function main() {
  const results = [];

  for (const name of cases) {
    const jsPath = path.join(corpusDir, name);
    const expectedPath = path.join(corpusDir, name.replace(/\.js$/, '.expected.json'));

    const [expected, actual] = await Promise.all([
      readExpected(expectedPath),
      evaluateFile(jsPath),
    ]);

    const passed =
      actual.contextValid === expected.context_valid &&
      actual.effectiveRisk === expected.effective_risk &&
      actual.finding === expected.finding;

    results.push({
      file: name,
      expectedContextValid: expected.context_valid,
      actualContextValid: actual.contextValid,
      expectedEffectiveRisk: expected.effective_risk,
      actualEffectiveRisk: actual.effectiveRisk,
      expectedFinding: expected.finding,
      actualFinding: actual.finding,
      passed,
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'ac005-context-validation',
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
