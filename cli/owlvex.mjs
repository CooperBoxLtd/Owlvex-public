/**
 * owlvex — deterministic security validation for modern codebases
 *
 * Usage:
 *   owlvex scan <dir>
 *   owlvex scan <dir> --report security-report.md
 *   owlvex scan <dir> --json
 *   owlvex scan <dir> --fail-on deterministic
 *   owlvex scan <dir> --report report.md --fail-on deterministic
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { resolve, join, extname, relative } from 'path';
import { buildMarkdownReport } from './report.mjs';

// ── Load scanner ───────────────────────────────────────────────────────────
// Static default import so esbuild can follow the dependency chain and
// inline DeterministicScanner into the bundle. The CJS module's exports
// land on the default export object in ESM.
import _scanner from './scanner.cjs';
const { DeterministicScanner } = _scanner;

// ── File walking ───────────────────────────────────────────────────────────

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', 'owlvex-dist']);
const SCAN_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);
const TEST_RE = /\.(test|spec)\.[jt]sx?$|__tests__/;

const EXT_TO_LANG = {
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascriptreact',
    '.ts': 'typescript',
    '.tsx': 'typescriptreact',
};

function walkDir(dir, files = []) {
    let entries;
    try {
        entries = readdirSync(dir, { withFileTypes: true });
    } catch {
        return files;
    }
    for (const entry of entries) {
        if (entry.isDirectory()) {
            if (!SKIP_DIRS.has(entry.name)) walkDir(join(dir, entry.name), files);
        } else if (entry.isFile()) {
            const ext = extname(entry.name);
            if (SCAN_EXTS.has(ext) && !TEST_RE.test(entry.name)) {
                files.push(join(dir, entry.name));
            }
        }
    }
    return files;
}

// ── Scanner wrapper ────────────────────────────────────────────────────────

function scanFile(filePath, rootDir) {
    let source;
    try {
        source = readFileSync(filePath, 'utf8');
    } catch {
        return null;
    }
    const ext = extname(filePath);
    const language = EXT_TO_LANG[ext] ?? 'javascript';
    const scanner = new DeterministicScanner();
    const findings = scanner.scan(source, language);
    if (!findings || findings.length === 0) return null;
    return {
        file: relative(rootDir, filePath).replace(/\\/g, '/'),
        findings,
    };
}

// ── CLI argument parsing ───────────────────────────────────────────────────

function parseArgs(argv) {
    const args = argv.slice(2);
    const command = args[0];
    let target = null;
    let reportPath = null;
    let jsonMode = false;
    let failOn = null;

    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--report' && args[i + 1]) {
            reportPath = args[++i];
        } else if (args[i] === '--json') {
            jsonMode = true;
        } else if (args[i] === '--fail-on' && args[i + 1]) {
            failOn = args[++i];
        } else if (!args[i].startsWith('--') && target === null) {
            target = args[i];
        }
    }

    return { command, target, reportPath, jsonMode, failOn };
}

// ── Main ───────────────────────────────────────────────────────────────────

function printUsage() {
    console.log(`
owlvex — deterministic security validation

Usage:
  owlvex scan <directory> [options]

Options:
  --report <file>         Write a markdown report to <file>
  --json                  Print JSON results to stdout
  --fail-on deterministic Exit with code 1 if any deterministic findings are found

Examples:
  owlvex scan .
  owlvex scan ./src --report report.md
  owlvex scan ./src --json
  owlvex scan ./src --report report.md --fail-on deterministic
`);
}

async function main() {
    const { command, target, reportPath, jsonMode, failOn } = parseArgs(process.argv);

    if (command !== 'scan' || !target) {
        printUsage();
        process.exit(command ? 1 : 0);
    }

    const rootDir = resolve(process.cwd(), target);

    // Verify target exists
    let targetStat;
    try {
        targetStat = statSync(rootDir);
    } catch {
        console.error(`owlvex: path not found: ${target}`);
        process.exit(2);
    }

    // Walk and scan
    let files;
    let scanRoot;
    if (targetStat.isFile()) {
        const ext = extname(rootDir);
        files = SCAN_EXTS.has(ext) ? [rootDir] : [];
        scanRoot = rootDir.replace(/\\/g, '/').split('/').slice(0, -1).join('/') || rootDir;
    } else {
        files = walkDir(rootDir);
        scanRoot = rootDir;
    }

    if (!jsonMode) {
        process.stderr.write(`\nOwlvex — scanning ${files.length} file${files.length !== 1 ? 's' : ''}...\n`);
    }

    const results = [];
    for (const filePath of files) {
        const result = scanFile(filePath, scanRoot);
        if (result) results.push(result);
    }

    const totalFindings = results.reduce((n, r) => n + r.findings.length, 0);
    // All findings from DeterministicScanner are deterministic (ruleCode is always present)
    const deterministicCount = totalFindings;

    // ── JSON output ────────────────────────────────────────────────────────

    if (jsonMode) {
        console.log(JSON.stringify({ scanned: files.length, results }, null, 2));
        if (failOn === 'deterministic' && deterministicCount > 0) process.exit(1);
        return;
    }

    // ── Terminal output ────────────────────────────────────────────────────

    if (totalFindings === 0) {
        console.log(`\n  No findings. ${files.length} file${files.length !== 1 ? 's' : ''} scanned.\n`);
    } else {
        console.log();
        for (const { file, findings } of results) {
            for (const f of findings) {
                const sev = f.severity?.toUpperCase().padEnd(8) ?? 'UNKNOWN ';
                const rule = f.ruleCode ? `⚡ ${f.ruleCode}` : '  ??';
                const line = f.line ? `:${f.line}` : '';
                console.log(`  ${rule}  ${sev}  ${file}${line}`);
                console.log(`           ${f.title}`);
            }
        }
        console.log();
        console.log(`  ${deterministicCount} deterministic finding${deterministicCount !== 1 ? 's' : ''}  |  ${files.length} file${files.length !== 1 ? 's' : ''} scanned`);
        console.log();
    }

    // ── Markdown report ────────────────────────────────────────────────────

    if (reportPath) {
        const report = buildMarkdownReport({ rootDir: target, scanned: files.length, results, scanRoot });
        const outPath = resolve(process.cwd(), reportPath);
        writeFileSync(outPath, report, 'utf8');
        console.log(`  Report written to ${reportPath}\n`);
    }

    // ── Exit code ──────────────────────────────────────────────────────────

    if (failOn === 'deterministic' && deterministicCount > 0) process.exit(1);
}

main().catch(err => {
    console.error('\nowlvex: unexpected error:', err.message);
    process.exit(2);
});
