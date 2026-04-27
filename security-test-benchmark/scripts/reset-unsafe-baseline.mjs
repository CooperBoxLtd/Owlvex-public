import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(__dirname, '..');
const apply = process.argv.includes('--apply');

function gitOutput(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
  });
}

const repoRoot = gitOutput(['rev-parse', '--show-toplevel'], appRoot).trim();
const appRepoPath = path.relative(repoRoot, appRoot).replace(/\\/g, '/');

const baselineFiles = [
  'src/routes/documents.js',
  'src/routes/refunds.js',
  'src/routes/roles.js',
  'src/routes/integrations.js',
  'src/routes/reports.js',
  'src/routes/profile.js',
  'src/routes/imports.js',
  'src/lib/tokens.js',
  'src/store/repositories.js',
];

function gitShow(relativePath) {
  return gitOutput(['show', `HEAD:${appRepoPath}/${relativePath}`], repoRoot);
}

function normalizeEol(value) {
  return value.replace(/\r\n/g, '\n');
}

function walkReports(directory, found = []) {
  if (!existsSync(directory)) {
    return found;
  }

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walkReports(fullPath, found);
    } else if (/^owlvex-(?:scan|summary)-report-\d+.*\.md$/i.test(entry.name)) {
      found.push(fullPath);
    }
  }
  return found;
}

const changed = [];
for (const relativePath of baselineFiles) {
  const target = path.join(appRoot, relativePath);
  const baseline = gitShow(relativePath);
  const current = existsSync(target) ? readFileSync(target, 'utf8') : '';
  if (normalizeEol(current) !== normalizeEol(baseline)) {
    changed.push(relativePath);
    if (apply) {
      writeFileSync(target, baseline, 'utf8');
    }
  }
}

const generatedSourceReports = walkReports(path.join(appRoot, 'src'));
if (apply) {
  for (const reportPath of generatedSourceReports) {
    rmSync(reportPath, { force: true });
  }
}

if (!apply) {
  console.log(changed.length
    ? `Unsafe baseline differs in ${changed.length} file(s): ${changed.join(', ')}`
    : 'Unsafe baseline source files already match HEAD.');
  if (generatedSourceReports.length) {
    console.log(`Generated reports under src would be removed: ${generatedSourceReports.map(file => path.relative(appRoot, file)).join(', ')}`);
  }
  process.exit(changed.length || generatedSourceReports.length ? 1 : 0);
}

console.log(`Restored unsafe benchmark baseline for ${changed.length} file(s).`);
if (generatedSourceReports.length) {
  console.log(`Removed ${generatedSourceReports.length} generated report(s) from src/.`);
}
