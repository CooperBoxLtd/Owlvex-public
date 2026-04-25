import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { repoRoot } from './owlvex-benchmark/repo-root.mjs';

const isWindows = process.platform === 'win32';
const shellProgram = isWindows ? 'cmd.exe' : '/bin/sh';
const shellArgs = isWindows ? ['/d', '/s', '/c'] : ['-lc'];

const checks = [
  {
    id: 'backend-tests',
    label: 'Backend tests',
    cwd: path.resolve(repoRoot, 'backend'),
    commandLines: [
      'python -m pytest -q',
      'py -3.12 -m pytest -q',
      'uv run --python 3.12 --with-requirements requirements.txt --with-requirements requirements-dev.txt pytest -q',
    ],
  },
  {
    id: 'extension-tests',
    label: 'Extension tests',
    cwd: path.resolve(repoRoot, 'extension'),
    commandLines: ['npm test -- --runInBand'],
  },
  {
    id: 'deterministic-benchmark',
    label: 'Deterministic benchmark',
    cwd: path.resolve(repoRoot, 'extension'),
    commandLines: ['npm run benchmark:deterministic'],
  },
  {
    id: 'benchmark-metrics',
    label: 'Benchmark direction metrics',
    cwd: path.resolve(repoRoot, 'extension'),
    commandLines: ['npm run benchmark:metrics'],
  },
];

function prefixLines(text, prefix) {
  return String(text)
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => `${prefix}${line}`)
    .join('\n');
}

function clipOutput(text, maxLines = 80) {
  const lines = String(text)
    .split(/\r?\n/)
    .filter((line) => line.length > 0);

  if (lines.length <= maxLines) {
    return lines.join('\n');
  }

  const headCount = Math.max(20, Math.floor(maxLines / 2));
  const tailCount = Math.max(20, maxLines - headCount - 1);
  const head = lines.slice(0, headCount);
  const tail = lines.slice(-tailCount);
  return [...head, `... (${lines.length - head.length - tail.length} lines omitted) ...`, ...tail].join('\n');
}

function matchUnique(lines, pattern) {
  return [...new Set(lines.filter((line) => pattern.test(line)))];
}

function summarizeCommandOutput(result) {
  const combined = `${result.stdout}\n${result.stderr}`;
  const lines = combined
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (result.status === 'blocked') {
    const blockedLines = matchUnique(lines, /Python was not found|is not recognized as the name of a cmdlet|is not recognized as an internal or external command|could not find files for the given pattern|command not found|No such file or directory|unable to find/i);
    if (blockedLines.length > 0) {
      return blockedLines.slice(0, 5);
    }
  }

  if (result.id === 'extension-tests') {
    const failedSuites = matchUnique(lines, /^FAIL\s+/).slice(0, 10);
    const totals = matchUnique(lines, /^(Test Suites:|Tests:|Snapshots:|Time:|Ran all test suites\.)/);
    const combinedSummary = [...failedSuites, ...totals];
    if (combinedSummary.length > 0) {
      return combinedSummary;
    }
  }

  const genericFailures = matchUnique(lines, /^(FAIL|Error:|Traceback|E\s)/).slice(0, 10);
  if (genericFailures.length > 0) {
    return genericFailures;
  }

  return clipOutput(combined.trim(), 40)
    .split(/\r?\n/)
    .filter((line) => line.length > 0);
}

function summarizeFailure(result) {
  if (result.status === 'blocked') {
    return `${result.label}: blocked`;
  }

  if (result.status === 'failed') {
    return `${result.label}: failed (exit ${result.exitCode ?? 'unknown'})`;
  }

  return `${result.label}: ${result.status}`;
}

async function runCheck(check) {
  const attempts = [];

  for (const commandLine of check.commandLines) {
    const result = await new Promise((resolve) => {
      const child = spawn(shellProgram, [...shellArgs, commandLine], {
        cwd: check.cwd,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (chunk) => {
        stdout += String(chunk);
      });

      child.stderr.on('data', (chunk) => {
        stderr += String(chunk);
      });

      child.on('error', (error) => {
        resolve({
          ...check,
          commandLine,
          status: 'blocked',
          exitCode: null,
          stdout,
          stderr,
          error: error.message,
        });
      });

      child.on('close', (code) => {
        const combinedOutput = `${stdout}\n${stderr}`;
        const blocked = code === 127
          || code === 9009
          || /Python was not found/i.test(combinedOutput)
          || /is not recognized as the name of a cmdlet/i.test(combinedOutput)
          || /is not recognized as an internal or external command/i.test(combinedOutput)
          || /Could not find files for the given pattern/i.test(combinedOutput)
          || /No module named pytest/i.test(combinedOutput)
          || /command not found/i.test(combinedOutput)
          || /No such file or directory/i.test(combinedOutput)
          || /unable to find/i.test(combinedOutput);
        resolve({
          ...check,
          commandLine,
          status: code === 0 ? 'passed' : blocked ? 'blocked' : 'failed',
          exitCode: code,
          stdout,
          stderr,
        });
      });
    });

    attempts.push({
      commandLine: result.commandLine,
      status: result.status,
      exitCode: result.exitCode,
    });

    if (result.status !== 'blocked') {
      return {
        ...result,
        attempts,
      };
    }
  }

  return {
    ...check,
    commandLine: check.commandLines[check.commandLines.length - 1],
    status: 'blocked',
    exitCode: null,
    stdout: '',
    stderr: '',
    error: 'No usable command was available for this check.',
    attempts,
  };
}

async function main() {
  const startedAt = new Date().toISOString();
  const results = [];

  for (const check of checks) {
    process.stdout.write(`\n==> ${check.label}\n`);
    const result = await runCheck(check);
    results.push(result);

    if (result.status !== 'passed') {
      const summaryLines = summarizeCommandOutput(result);
      if (summaryLines.length > 0) {
        process.stdout.write(`${prefixLines(summaryLines.join('\n'), '  ')}\n`);
      }
    }

    if (result.status === 'blocked' && result.error) {
      process.stderr.write(`  ${result.error}\n`);
    }

    process.stdout.write(`  status: ${result.status}${result.exitCode !== null ? ` (exit ${result.exitCode})` : ''}\n`);
  }

  const failed = results.filter((result) => result.status === 'failed');
  const blocked = results.filter((result) => result.status === 'blocked');
  const passed = results.filter((result) => result.status === 'passed');
  const overallStatus = failed.length > 0
    ? 'failed'
    : blocked.length > 0
      ? 'blocked'
      : 'passed';

  const summary = {
    startedAt,
    finishedAt: new Date().toISOString(),
    overallStatus,
    releaseReadiness: overallStatus === 'passed' ? 'candidate' : 'not-ready',
    checks: results.map((result) => ({
      id: result.id,
      label: result.label,
      status: result.status,
      exitCode: result.exitCode,
      cwd: result.cwd,
      commandLine: result.commandLine,
      attempts: result.attempts ?? [],
      error: result.error ?? null,
    })),
  };

  process.stdout.write('\nRelease check summary\n');
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);

  if (overallStatus !== 'passed') {
    const messages = [...failed, ...blocked].map(summarizeFailure).join('; ');
    throw new Error(`Release check ${overallStatus}: ${messages}`);
  }

  process.stdout.write('\nRelease check passed.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
