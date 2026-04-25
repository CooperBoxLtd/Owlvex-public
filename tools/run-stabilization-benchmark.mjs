import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const extensionRoot = path.join(repoRoot, 'extension');

function countExpectationRows(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return content
    .split(/\r?\n/)
    .filter(line => /^\| `.+` \|/.test(line))
    .length;
}

const demoExpectationCount = countExpectationRows(path.join(repoRoot, 'tools', 'demo', 'EXPECTATIONS.md'));
const demoAppExpectationCount = countExpectationRows(path.join(repoRoot, 'tools', 'demo-app', 'EXPECTATIONS.md'));
const benchmarkAppExpectationCount = countExpectationRows(path.join(repoRoot, 'tools', 'benchmark-app', 'EXPECTATIONS.md'));

console.log('Owlvex stabilization benchmark');
console.log(`- demo expectations: ${demoExpectationCount}`);
console.log(`- demo-app expectations: ${demoAppExpectationCount}`);
console.log(`- benchmark-app expectations: ${benchmarkAppExpectationCount}`);

const result = spawnSync(
  process.platform === 'win32' ? 'npm.cmd' : 'npm',
  [
    'test',
    '--',
    '--runInBand',
    '--runTestsByPath',
    'src/scanner/demoRegression.test.ts',
    'src/scanner/scanEngine.test.ts',
    'src/scanner/workspaceScanner.test.ts',
    'src/scanner/reportGenerator.test.ts',
    'src/panels/sidebarProvider.test.ts',
  ],
  {
    cwd: extensionRoot,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  },
);

if (result.error) {
  console.error(`Failed to launch stabilization benchmark: ${result.error.message}`);
  process.exit(1);
}

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

console.log('Stabilization benchmark passed.');
