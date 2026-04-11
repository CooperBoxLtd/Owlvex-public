import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/sql_query');
const cases = [
  'direct_query_positive.js',
  'parameterized_query_negative.js',
  'conditional_query_edge.js',
  'wrapped_query_edge.js',
  'html_to_sql_positive.js',
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
      expectedType: expected.type,
      actualType: actual.type,
      expectedFinding: expected.finding,
      actualFinding: actual.finding,
      sink: actual.sink,
      parameterized: actual.parameterized,
      passed:
        actual.type === expected.type
        && actual.finding === expected.finding,
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'sq001-query-injection-decision',
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
