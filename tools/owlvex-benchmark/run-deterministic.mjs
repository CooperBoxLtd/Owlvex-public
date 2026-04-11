import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { extensionRoot, repoRoot } from './repo-root.mjs';

const suites = [
  { name: 'gr002', command: ['run', 'benchmark:gr002'] },
  { name: 'gr003', command: ['run', 'benchmark:gr003'] },
  { name: 'gr004', command: ['run', 'benchmark:gr004'] },
  { name: 'gr005', command: ['run', 'benchmark:gr005'] },
  { name: 'gr001', command: ['run', 'benchmark:gr001'] },
  { name: 'integration', command: ['run', 'benchmark:integration'] },
  { name: 'sq002', command: ['run', 'benchmark:sq002'] },
  { name: 'sq003', command: ['run', 'benchmark:sq003'] },
  { name: 'sq004', command: ['run', 'benchmark:sq004'] },
  { name: 'sq005', command: ['run', 'benchmark:sq005'] },
  { name: 'sq001', command: ['run', 'benchmark:sq001'] },
  { name: 'sql-integration', command: ['run', 'benchmark:sql-integration'] },
  { name: 'ac002', command: ['run', 'benchmark:ac002'] },
  { name: 'ac004', command: ['run', 'benchmark:ac004'] },
  { name: 'ac003', command: ['run', 'benchmark:ac003'] },
  { name: 'ac005', command: ['run', 'benchmark:ac005'] },
  { name: 'ac001', command: ['run', 'benchmark:ac001'] },
  { name: 'ac-integration', command: ['run', 'benchmark:ac-integration'] },
  { name: 'sm002', command: ['run', 'benchmark:sm002'] },
];

const runsDir = path.resolve(repoRoot, 'tools/owlvex-benchmark/runs/deterministic');

function runSuite({ name, command }) {
  const isWindows = process.platform === 'win32';
  const executable = isWindows ? (process.env.ComSpec || 'cmd.exe') : 'npm';
  const args = isWindows
    ? ['/d', '/s', '/c', `npm ${command.join(' ')}`]
    : command;
  const result = spawnSync(executable, args, {
    cwd: extensionRoot,
    stdio: 'pipe',
    encoding: 'utf8',
    shell: false,
  });

  return {
    name,
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    passed: (result.status ?? 1) === 0,
  };
}

function parseSuiteSummary(result) {
  const trimmed = result.stdout.trim();
  const jsonStart = trimmed.lastIndexOf('\n{');
  const candidate = jsonStart >= 0 ? trimmed.slice(jsonStart + 1) : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
}

function toTimestamp(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function toCompactSummary(summary) {
  const suiteResults = summary.results.map((entry) => ({
    name: entry.name,
    passed: entry.passed,
    exitCode: entry.exitCode,
    suite: entry.summary?.suite ?? null,
    casesPassed: typeof entry.summary?.passed === 'number' ? entry.summary.passed : null,
    casesTotal: typeof entry.summary?.total === 'number' ? entry.summary.total : null,
  }));

  const totalCases = suiteResults.reduce(
    (total, entry) => total + (typeof entry.casesTotal === 'number' ? entry.casesTotal : 0),
    0,
  );
  const passedCases = suiteResults.reduce(
    (total, entry) => total + (typeof entry.casesPassed === 'number' ? entry.casesPassed : 0),
    0,
  );

  return {
    suite: summary.suite,
    generatedAt: summary.generatedAt,
    passed: summary.passed,
    totalSuites: summary.results.length,
    passedSuites: suiteResults.filter((entry) => entry.passed).length,
    totalCases,
    passedCases,
    failedSuite: summary.failedSuite ?? null,
    results: suiteResults,
  };
}

async function writeRunArtifacts(summary) {
  await fs.mkdir(runsDir, { recursive: true });
  const timestamp = toTimestamp(new Date(summary.generatedAt));
  const latestPath = path.join(runsDir, 'latest.json');
  const historicalPath = path.join(runsDir, `${timestamp}.json`);
  const latestFullPath = path.join(runsDir, 'latest.full.json');
  const historicalFullPath = path.join(runsDir, `${timestamp}.full.json`);
  const compactSummary = toCompactSummary(summary);
  const compactBody = `${JSON.stringify(compactSummary, null, 2)}\n`;
  const fullBody = `${JSON.stringify(summary, null, 2)}\n`;

  await fs.writeFile(latestPath, compactBody, 'utf8');
  await fs.writeFile(historicalPath, compactBody, 'utf8');
  await fs.writeFile(latestFullPath, fullBody, 'utf8');
  await fs.writeFile(historicalFullPath, fullBody, 'utf8');
}

async function main() {
  const results = [];
  const generatedAt = new Date().toISOString();

  for (const suite of suites) {
    const result = runSuite(suite);
    const parsed = parseSuiteSummary(result);
    results.push(result);

    if (!result.passed) {
      const summary = {
        suite: 'deterministic-axis',
        generatedAt,
        passed: false,
        failedSuite: result.name,
        results: results.map((entry) => ({
          name: entry.name,
          exitCode: entry.exitCode,
          passed: entry.passed,
          summary: parseSuiteSummary(entry),
        })),
      };
      await writeRunArtifacts(summary);
      console.error(JSON.stringify(summary, null, 2));
      process.stderr.write(result.stdout);
      process.stderr.write(result.stderr);
      process.exitCode = 1;
      return;
    }

    result.summary = parsed;
  }

  const summary = {
    suite: 'deterministic-axis',
    generatedAt,
    passed: true,
    total: results.length,
    results: results.map((entry) => ({
      name: entry.name,
      exitCode: entry.exitCode,
      passed: entry.passed,
      summary: entry.summary ?? null,
    })),
  };
  await writeRunArtifacts(summary);
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
