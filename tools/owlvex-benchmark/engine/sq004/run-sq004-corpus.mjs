import fs from 'node:fs/promises';
import path from 'node:path';

import { evaluateFile } from './evaluator.mjs';
import { repoRoot } from '../../repo-root.mjs';

const corpusDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/corpus/sql_query');
const cases = [
  'direct_query_positive.js',
  'parameterized_query_negative.js',
  'wrapped_query_edge.js',
];

async function listCorpusCases() {
  return cases.map((name) => ({
    jsPath: path.join(corpusDir, name),
  }));
}

function expectedForFile(file) {
  const expectations = {
    'direct_query_positive.js': {
      sink: 'db.query',
      parameterized: false,
      viaWrapper: false,
      queryExpression: 'query',
    },
    'parameterized_query_negative.js': {
      sink: 'db.query',
      parameterized: true,
      viaWrapper: false,
      queryExpression: 'query',
    },
    'wrapped_query_edge.js': {
      sink: 'db.query',
      parameterized: false,
      viaWrapper: true,
      queryExpression: 'query',
    },
  };

  return expectations[file];
}

async function main() {
  const corpusCases = await listCorpusCases();
  const results = [];

  for (const corpusCase of corpusCases) {
    const actual = await evaluateFile(corpusCase.jsPath);
    const expected = expectedForFile(path.basename(corpusCase.jsPath));
    results.push({
      file: path.basename(corpusCase.jsPath),
      expectedSink: expected.sink,
      actualSink: actual.sink,
      expectedParameterized: expected.parameterized,
      actualParameterized: actual.parameterized,
      expectedViaWrapper: expected.viaWrapper,
      actualViaWrapper: actual.viaWrapper,
      expectedQueryExpression: expected.queryExpression,
      actualQueryExpression: actual.queryExpression,
      passed:
        actual.sink === expected.sink
        && actual.parameterized === expected.parameterized
        && actual.viaWrapper === expected.viaWrapper
        && actual.queryExpression === expected.queryExpression,
    });
  }

  const passed = results.filter((result) => result.passed).length;
  console.log(JSON.stringify({
    suite: 'sq004-query-sink-shape',
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
