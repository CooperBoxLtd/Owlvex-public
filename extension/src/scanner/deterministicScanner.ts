/**
 * DeterministicScanner
 *
 * Pattern-based, zero-dependency scanner that runs on source code strings.
 * Detects high-confidence injection sinks without requiring AI or backend calls.
 *
 * Covers:
 *   GR-001 — Command/shell injection via template literal interpolation
 *   SQ-001 — SQL injection via template literal interpolation
 *   SQ-005 — SQL context mismatch (HTML sanitizer applied before SQL sink)
 *
 * These findings have confidence = 1 because the pattern is unambiguous:
 * a template literal is structurally interpolated into a dangerous sink call.
 * Whether the interpolated value is ultimately user-controlled is left to the
 * developer to confirm, but the shape is always a defect candidate.
 */

import * as crypto from 'crypto';
import type { Finding } from './scanEngine';

const SUPPORTED_LANGUAGES = new Set([
    'javascript', 'javascriptreact', 'typescript', 'typescriptreact',
]);

// HTML-oriented sanitizers that are NOT valid for SQL context.
const HTML_SANITIZERS = [
    'escapeHtml', 'htmlspecialchars', 'encodeHtml', 'htmlEscape', 'escapeXml',
];

// GR-001: shell sink names that accept a command string argument.
// Matches exec(), execSync(), spawn(), spawnSync(), execFile(), execFileSync().
const SHELL_SINK_PATTERN =
    /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`/g;

// SQ-001: SQL sink call with a template literal as the first argument (inline).
// Matches db.query(`...${x}...`) — excludes parameterized (.query('...', [...])).
const SQL_SINK_INLINE_PATTERN =
    /\.(query|execute|raw)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`/g;

// SQ-001: SQL sink call with a plain variable as the first argument.
// Catches db.query(queryVar) when queryVar was assigned a template literal.
const SQL_SINK_VAR_PATTERN =
    /\.(query|execute|raw)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[,)]/g;

// Template literal assignment: const query = `SELECT ... ${x} ...`
const TEMPLATE_ASSIGN_PATTERN =
    /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*`([^`]*\$\{[^}]+\}[^`]*)`/g;

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface InternalFinding {
    matchIndex: number;
    severity: Severity;
    ruleCode: string;
    title: string;
    explanation: string;
    threat: string;
    fix: string;
    canonicalId: string;
    framework: string;
}

function lineOfOffset(source: string, offset: number): number {
    let line = 1;
    for (let i = 0; i < offset && i < source.length; i += 1) {
        if (source[i] === '\n') {
            line += 1;
        }
    }
    return line;
}

function hasHtmlSanitizerBefore(source: string, sinkOffset: number): boolean {
    const prefix = source.slice(0, sinkOffset);
    return HTML_SANITIZERS.some(fn => prefix.includes(`${fn}(`));
}

function scanShellSinks(source: string): InternalFinding[] {
    const found: InternalFinding[] = [];
    const pattern = new RegExp(SHELL_SINK_PATTERN.source, SHELL_SINK_PATTERN.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(source)) !== null) {
        found.push({
            matchIndex: match.index,
            severity: 'HIGH',
            ruleCode: 'GR-001',
            title: 'Command Injection',
            explanation:
                `A template literal containing an interpolated value reaches a shell ` +
                `execution sink (\`${match[1]}\`). If the interpolated value originates ` +
                `from user-controlled input this is directly exploitable.`,
            threat:
                'An attacker can inject arbitrary shell commands and execute them with ' +
                'the privileges of the server process.',
            fix:
                'Avoid building shell commands from strings. Use child_process.execFile ' +
                'with a separate argument array, or a library that escapes shell metacharacters.',
            canonicalId: 'owlvex.issue.command_injection.001',
            framework: 'OWASP',
        });
    }

    return found;
}

function makeSqlFinding(matchIndex: number, contextMismatch: boolean, sinkName: string): InternalFinding {
    if (contextMismatch) {
        return {
            matchIndex,
            severity: 'HIGH',
            ruleCode: 'SQ-001',
            title: 'SQL Injection — Ineffective HTML Sanitizer',
            explanation:
                'A value processed through an HTML-oriented sanitizer is interpolated ' +
                'into SQL query text. HTML escaping does not provide SQL injection ' +
                'protection and leaves the query vulnerable.',
            threat:
                'An attacker can manipulate SQL queries to read, modify, or delete data, ' +
                'or bypass authentication.',
            fix:
                'Use parameterized queries or prepared statements. Pass user input as a ' +
                'bound parameter rather than as part of the query string. HTML escaping ' +
                'is not a substitute for SQL parameterization.',
            canonicalId: 'owlvex.issue.sql_injection.001',
            framework: 'OWASP',
        };
    }

    return {
        matchIndex,
        severity: 'HIGH',
        ruleCode: 'SQ-001',
        title: 'SQL Injection',
        explanation:
            `A template literal containing an interpolated value reaches a SQL ` +
            `query sink (\`.${sinkName}\`). If the interpolated value originates ` +
            'from user-controlled input this is directly exploitable.',
        threat:
            'An attacker can manipulate SQL queries to read, modify, or delete data, ' +
            'or bypass authentication.',
        fix:
            'Use parameterized queries or prepared statements. Pass user input as a ' +
            'bound parameter, not as part of the query string.',
        canonicalId: 'owlvex.issue.sql_injection.001',
        framework: 'OWASP',
    };
}

function scanSqlSinks(source: string): InternalFinding[] {
    const found: InternalFinding[] = [];

    // Collect template literal assignments: `const query = \`SELECT ${x}\``
    const templateVars = new Set<string>();
    const assignPattern = new RegExp(TEMPLATE_ASSIGN_PATTERN.source, TEMPLATE_ASSIGN_PATTERN.flags);
    let match: RegExpExecArray | null;
    while ((match = assignPattern.exec(source)) !== null) {
        templateVars.add(match[1]);
    }

    // Case A: inline template literal passed directly to the sink.
    const inlinePattern = new RegExp(SQL_SINK_INLINE_PATTERN.source, SQL_SINK_INLINE_PATTERN.flags);
    while ((match = inlinePattern.exec(source)) !== null) {
        found.push(makeSqlFinding(match.index, hasHtmlSanitizerBefore(source, match.index), match[1]));
    }

    // Case B: variable previously assigned a template literal passed to the sink.
    const varPattern = new RegExp(SQL_SINK_VAR_PATTERN.source, SQL_SINK_VAR_PATTERN.flags);
    while ((match = varPattern.exec(source)) !== null) {
        const varName = match[2];
        if (templateVars.has(varName)) {
            found.push(makeSqlFinding(match.index, hasHtmlSanitizerBefore(source, match.index), match[1]));
        }
    }

    return found;
}

export class DeterministicScanner {
    scan(source: string, language: string): Partial<Finding>[] {
        if (!SUPPORTED_LANGUAGES.has(language)) {
            return [];
        }

        const internal: InternalFinding[] = [
            ...scanShellSinks(source),
            ...scanSqlSinks(source),
        ];

        return internal.map(f => ({
            id: crypto.randomUUID(),
            line: lineOfOffset(source, f.matchIndex),
            lineEnd: lineOfOffset(source, f.matchIndex),
            severity: f.severity,
            framework: f.framework,
            ruleCode: f.ruleCode,
            title: f.title,
            explanation: f.explanation,
            threat: f.threat,
            fix: f.fix,
            confidence: 1,
            canonicalId: f.canonicalId,
        }));
    }
}
