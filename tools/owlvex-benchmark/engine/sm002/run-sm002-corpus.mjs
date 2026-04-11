import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/debug_mode');

const cases = [
  'unconditional_positive.js',
  'enable_unguarded_positive.js',
  'guarded_negative.js',
  'no_debug_activation_negative.js',
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
      actual.finding === expected.finding &&
      actual.hasEnvContext === expected.has_env_context &&
      actual.hasDebugActivation === expected.has_debug_activation;

    results.push({
      file: name,
      expectedFinding: expected.finding,
      actualFinding: actual.finding,
      expectedEnvContext: expected.has_env_context,
      actualEnvContext: actual.hasEnvContext,
      expectedDebugActivation: expected.has_debug_activation,
      actualDebugActivation: actual.hasDebugActivation,
      passed,
    });
  }

  const passed = results.filter((r) => r.passed).length;
  console.log(JSON.stringify({
    suite: 'sm002-debug-mode',
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
