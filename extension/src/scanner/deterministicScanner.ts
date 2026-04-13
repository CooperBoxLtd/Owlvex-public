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
 *   AC-001 — Insecure Direct Object Reference (IDOR / BOLA)
 *
 * These findings have confidence = 1 because the pattern is unambiguous:
 * a template literal is structurally interpolated into a dangerous sink call,
 * or a caller-supplied identifier reaches a data store without authorization.
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

// GR-001: shell-parsed command string sinks.
// Matches exec()/execSync() only. Other process APIs require separate modeling.
const SHELL_SINK_PATTERN =
    /\b(exec|execSync)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`/g;

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

// HTML sanitizer assignment: const cleaned = escapeHtml(username)
const SANITIZER_ASSIGN_PATTERN =
    /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:escapeHtml|htmlspecialchars|encodeHtml|htmlEscape|escapeXml)\s*\(/g;

// ==================== AC-001: IDOR / Access Control ====================

// Caller-supplied resource identifier parameter names.
// These appear as function/route handler params that could be manipulated.
const IDOR_UNTRUSTED_PARAM_RE =
    /^(userId|docId|id|resourceId|requestedId|postId|commentId|orderId|itemId|\w+Id)$/;

// Session-bound expression — if present in query args the resource is OWNED.
const IDOR_SESSION_ARG_RE =
    /\b(currentUser|user|authUser|me|session|principal)\.(id|userId)\b/;

// DB query call with a parameterized args array.
const IDOR_QUERY_PARAMS_RE =
    /\.(query|execute|raw)\s*\(\s*(?:`[^`]*`|'[^']*'|"[^"]*")\s*,\s*\[([^\]]{0,400})\]/g;

// Authorization check patterns — any of these in the body → no IDOR finding.
const IDOR_AUTH_CHECK_RE =
    /\b(authorize|hasPermission|canAccess|authz|isAdmin|hasRole|checkRole|requireRole|checkPermission|requirePermission)\s*\(/;

// Auth-only pattern — logged-in check only (insufficient for object-level authorization).
const IDOR_AUTH_ONLY_RE =
    /\b(isAuthenticated|requireAuth|checkAuth|ensureAuth|verifyAuth)\s*\(/;

// Function/arrow function definition patterns.
const IDOR_FUNC_DEF_RE =
    /(?:async\s+)?function\s*(?:\w+\s*)?\(([^)]{0,300})\)\s*\{|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\(([^)]{0,300})\)\s*=>\s*\{/g;

function extractBodyAfterBrace(source: string, braceOffset: number): string {
    // source[braceOffset] should be the opening '{' of the function body.
    let balance = 1;
    let i = braceOffset + 1;
    let inString = false;
    let stringChar = '';

    while (i < source.length && balance > 0) {
        const ch = source[i];
        if (inString) {
            if (ch === '\\') { i += 2; continue; }
            if (ch === stringChar) { inString = false; }
            i++;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            inString = true;
            stringChar = ch;
        } else if (ch === '{') {
            balance++;
        } else if (ch === '}') {
            balance--;
        }
        i++;
    }
    return source.slice(braceOffset + 1, i - 1);
}

function idorHasIdInArgs(argsText: string, untrustedParams: string[]): boolean {
    const args = argsText.split(',').map(a => a.trim());
    return args.some(arg => untrustedParams.includes(arg));
}

function scanIdorSinks(source: string): InternalFinding[] {
    const found: InternalFinding[] = [];
    const funcPattern = new RegExp(IDOR_FUNC_DEF_RE.source, IDOR_FUNC_DEF_RE.flags);

    let match: RegExpExecArray | null;
    while ((match = funcPattern.exec(source)) !== null) {
        const paramsText = (match[1] ?? match[2] ?? '');
        const params = paramsText.split(',').map(p => p.trim()).filter(Boolean);
        const untrustedParams = params.filter(p => IDOR_UNTRUSTED_PARAM_RE.test(p));

        if (untrustedParams.length === 0) { continue; }

        // The function match ends with '{'; extract the body from that brace.
        const braceOffset = match.index + match[0].length - 1;
        const body = extractBodyAfterBrace(source, braceOffset);

        // Check for a parameterized query with the untrusted ID in the args array.
        const qPattern = new RegExp(IDOR_QUERY_PARAMS_RE.source, IDOR_QUERY_PARAMS_RE.flags);
        let queryMatch: RegExpExecArray | null;
        let hasVulnerableQuery = false;

        while ((queryMatch = qPattern.exec(body)) !== null) {
            const argsText = queryMatch[2] ?? '';
            if (IDOR_SESSION_ARG_RE.test(argsText)) { continue; }
            if (idorHasIdInArgs(argsText, untrustedParams)) {
                hasVulnerableQuery = true;
                break;
            }
        }

        if (!hasVulnerableQuery) { continue; }

        // If an explicit authorization check is present the access is controlled.
        if (IDOR_AUTH_CHECK_RE.test(body)) { continue; }

        const isAuthOnly = IDOR_AUTH_ONLY_RE.test(body);

        found.push({
            matchIndex: match.index,
            severity: 'HIGH',
            ruleCode: 'AC-001',
            title: isAuthOnly
                ? 'Insecure Direct Object Reference — Authentication Without Authorization'
                : 'Insecure Direct Object Reference',
            explanation: isAuthOnly
                ? `The function accepts \`${untrustedParams.join(', ')}\` as a caller-supplied ` +
                  `identifier and queries the database using that value. An authentication check ` +
                  `confirms the caller is logged in, but no ownership or permission check verifies ` +
                  `that this caller is entitled to access the specific record identified. ` +
                  `Authentication proves identity — it does not grant authorization to a resource.`
                : `The function accepts \`${untrustedParams.join(', ')}\` as a caller-supplied ` +
                  `identifier and queries the database using that value directly. ` +
                  `No ownership constraint or permission check is present in the function body. ` +
                  `Any caller who can reach this endpoint can retrieve records belonging to other users ` +
                  `by substituting a different identifier value.`,
            threat:
                'An attacker authenticated as any user can enumerate records belonging to ' +
                'other accounts by iterating or brute-forcing the identifier. ' +
                'Depending on the resource, this enables cross-account data disclosure, ' +
                'modification, or deletion without requiring elevated privileges.',
            fix:
                `Add an ownership constraint to the query: ` +
                `\`WHERE id = ? AND user_id = currentUser.id\`. ` +
                `Alternatively, perform an explicit authorization check ` +
                `(\`authorize(currentUser, 'read', ${untrustedParams[0]})\`) ` +
                `before the query and return HTTP 403 if it fails. ` +
                `The check must happen at the data layer — API-level guards are insufficient ` +
                `if the function is reachable through multiple call paths.`,
            canonicalId: 'owlvex.issue.idor.001',
            framework: 'OWASP',
        });
    }

    return found;
}

// ==================== End AC-001 ====================

// ==================== AC-T001: Multi-Tenant Isolation =====================

/**
 * Tenant context signals — if ANY of these appear in the source the file
 * is operating in (or adjacent to) a multi-tenant model. Only then do we
 * run the tenant isolation check.
 *
 * This is the heuristic gate that prevents false positives on single-tenant
 * codebases that have no concept of tenants.
 */
const TENANT_CONTEXT_SIGNALS = [
    'tenantId', 'organizationId', 'orgId', 'workspaceId',
    'accountId', 'companyId', 'tenantContext', 'tenantScope',
];

// Tenant ID parameter names in function signatures.
const TENANT_PARAM_RE =
    /^(tenantId|organizationId|orgId|workspaceId|accountId|companyId|tenantContext|tenantScope)$/;

// Detects whether a query's args array includes a tenant identifier.
const TENANT_ARG_RE =
    /\b(tenantId|organizationId|orgId|workspaceId|accountId|companyId|tenantContext|tenantScope)\b/;

function hasTenantContext(source: string): boolean {
    return TENANT_CONTEXT_SIGNALS.some(signal => source.includes(signal));
}

function scanTenantIsolationSinks(source: string): InternalFinding[] {
    // Heuristic gate — only scan when the source shows multi-tenant signals.
    // This is the line that prevents false positives in single-tenant apps.
    if (!hasTenantContext(source)) { return []; }

    const found: InternalFinding[] = [];
    const funcPattern = new RegExp(IDOR_FUNC_DEF_RE.source, IDOR_FUNC_DEF_RE.flags);

    let match: RegExpExecArray | null;
    while ((match = funcPattern.exec(source)) !== null) {
        const paramsText = (match[1] ?? match[2] ?? '');
        const params = paramsText.split(',').map(p => p.trim()).filter(Boolean);
        const tenantParams = params.filter(p => TENANT_PARAM_RE.test(p));

        if (tenantParams.length === 0) { continue; }

        const braceOffset = match.index + match[0].length - 1;
        const body = extractBodyAfterBrace(source, braceOffset);

        // Look for a parameterized DB query in this function body.
        const qPattern = new RegExp(IDOR_QUERY_PARAMS_RE.source, IDOR_QUERY_PARAMS_RE.flags);
        let queryMatch: RegExpExecArray | null;
        let hasMissingTenantConstraint = false;

        while ((queryMatch = qPattern.exec(body)) !== null) {
            const argsText = queryMatch[2] ?? '';
            // If the query args do NOT include the tenant ID → isolation missing.
            if (!TENANT_ARG_RE.test(argsText)) {
                hasMissingTenantConstraint = true;
                break;
            }
        }

        if (!hasMissingTenantConstraint) { continue; }

        found.push({
            matchIndex: match.index,
            severity: 'CRITICAL',
            ruleCode: 'AC-T001',
            title: 'Multi-Tenant Isolation Failure',
            explanation:
                `The function accepts \`${tenantParams.join(', ')}\` as a parameter that ` +
                `identifies the intended tenant scope, but the database query does not include ` +
                `that identifier as a WHERE clause constraint. ` +
                `The tenant boundary exists at the API layer but is not enforced at the data layer.`,
            threat:
                'An attacker authenticated in one tenant can retrieve, modify, or delete records ' +
                'belonging to any other tenant by calling this endpoint. ' +
                'The missing constraint means the query returns results from all tenants ' +
                'regardless of the caller\'s identity — a horizontal privilege escalation ' +
                'that scales with the number of tenants in the system.',
            fix:
                `Add \`${tenantParams[0]}\` to the query WHERE clause as a bound parameter: ` +
                `\`WHERE ... AND tenant_id = ?\` with \`${tenantParams[0]}\` in the args array. ` +
                `Enforce this constraint at the repository or data-access layer so that ` +
                `future callers cannot accidentally omit it. ` +
                `If the function should operate across tenants (e.g., an admin endpoint), ` +
                `document that explicitly and guard it with a role check.`,
            canonicalId: 'owlvex.issue.tenant_isolation_missing.001',
            framework: 'OWASP',
        });
    }

    return found;
}

// ==================== End AC-T001 ====================

// ==================== Shared paren/arg helpers ====================

/**
 * Extracts the text between a matched open-paren and its balanced close-paren.
 * source[openParenOffset] must be '('.
 */
function extractArgsAfterParen(source: string, openParenOffset: number): string {
    let balance = 1;
    let i = openParenOffset + 1;
    let inString = false;
    let stringChar = '';

    while (i < source.length && balance > 0) {
        const ch = source[i];
        if (inString) {
            if (ch === '\\') { i += 2; continue; }
            if (ch === stringChar) { inString = false; }
            i++;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            inString = true;
            stringChar = ch;
        } else if (ch === '(') {
            balance++;
        } else if (ch === ')') {
            balance--;
        }
        i++;
    }
    return source.slice(openParenOffset + 1, i - 1);
}

/**
 * Splits a flat argument text at top-level commas, respecting parens, brackets,
 * braces, and string literals.
 */
function splitTopLevelArgs(argsText: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let inString = false;
    let stringChar = '';
    let start = 0;

    for (let i = 0; i < argsText.length; i++) {
        const ch = argsText[i];
        if (inString) {
            if (ch === '\\') { i++; continue; }
            if (ch === stringChar) { inString = false; }
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            inString = true; stringChar = ch; continue;
        }
        if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
        if (ch === ')' || ch === ']' || ch === '}') { depth--; continue; }
        if (ch === ',' && depth === 0) {
            parts.push(argsText.slice(start, i).trim());
            start = i + 1;
        }
    }
    parts.push(argsText.slice(start).trim());
    return parts;
}

// ==================== End shared helpers ====================

// ==================== DP-001: PII / Sensitive Data in Logs ====================

/**
 * PII field names that should never appear in log output.
 * Doubles as the heuristic gate — if none of these strings appear in the
 * source the scanner exits immediately with no findings.
 */
const PII_CONTEXT_SIGNALS = [
    'password', 'ssn', 'socialSecurityNumber', 'dateOfBirth',
    'creditCard', 'cardNumber', 'cvv', 'accessToken', 'refreshToken',
    'privateKey', 'secretKey', 'apiSecret',
];

// Pattern to locate the start of a logging call (ends with the open paren).
const LOG_CALL_START_RE =
    /\b(?:console\.(?:log|info|warn|error|debug)|logger\.(?:info|warn|error|debug|trace|log)|log\.(?:info|warn|error|debug|trace))\s*\(/g;

// Matches a PII field name as an identifier token inside log arguments.
const PII_FIELD_IN_LOG_RE =
    /\b(?:password|ssn|socialSecurityNumber|dateOfBirth|creditCard|cardNumber|cvv|accessToken|refreshToken|privateKey|secretKey|apiSecret)\b/;

function scanPiiLoggingSinks(source: string): InternalFinding[] {
    // Heuristic gate — only scan when a PII field name appears anywhere in the source.
    if (!PII_CONTEXT_SIGNALS.some(s => source.includes(s))) { return []; }

    const found: InternalFinding[] = [];
    const pattern = new RegExp(LOG_CALL_START_RE.source, LOG_CALL_START_RE.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(source)) !== null) {
        // The last character of the match is '(' — that is the open paren.
        const openParen = match.index + match[0].length - 1;
        const args = extractArgsAfterParen(source, openParen);
        const piiMatch = PII_FIELD_IN_LOG_RE.exec(args);
        if (!piiMatch) { continue; }

        found.push({
            matchIndex: match.index,
            severity: 'HIGH',
            ruleCode: 'DP-001',
            title: 'Sensitive Data Exposure in Log Output',
            explanation:
                `A logging call includes a sensitive field (\`${piiMatch[0]}\`) in its arguments. ` +
                `Log output is typically persisted in log aggregation systems that may be accessible ` +
                `to operations staff, third-party vendors, or attackers who gain log access.`,
            threat:
                'Sensitive fields written to logs can be harvested by anyone with log access, ' +
                'including aggregation platforms, SIEM systems, and external log vendors.',
            fix:
                'Remove sensitive fields from log arguments. If diagnostic context is required, ' +
                'log a masked representation (e.g., presence/absence of a token, last 4 digits of a card) ' +
                'rather than the raw value.',
            canonicalId: 'owlvex.issue.sensitive_logging.001',
            framework: 'OWASP',
        });
    }

    return found;
}

// ==================== End DP-001 ====================

// ==================== SM-001: Insecure Cookie Flags ====================

/**
 * Matches the start of a res.cookie() call in Express-style handlers.
 * We restrict to `res.cookie` rather than the generic `.cookie` to avoid
 * false positives on client-side cookie libraries with different signatures.
 */
const COOKIE_CALL_START_RE = /\bres\.cookie\s*\(/g;

// httpOnly: true must be present in the options object to prevent JS access.
const HTTPONLY_TRUE_RE = /\bhttpOnly\s*:\s*true\b/;

function scanInsecureCookieSinks(source: string): InternalFinding[] {
    // Heuristic gate — only scan files that contain a res.cookie call.
    if (!source.includes('res.cookie(')) { return []; }

    const found: InternalFinding[] = [];
    const pattern = new RegExp(COOKIE_CALL_START_RE.source, COOKIE_CALL_START_RE.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(source)) !== null) {
        const openParen = match.index + match[0].length - 1;
        const argsText = extractArgsAfterParen(source, openParen);
        const parts = splitTopLevelArgs(argsText);

        // Must have at least cookie name + value to be a valid set call.
        if (parts.length < 2) { continue; }

        if (parts.length === 2) {
            // No options argument — httpOnly defaults to false in Express.
            found.push({
                matchIndex: match.index,
                severity: 'MEDIUM',
                ruleCode: 'SM-001',
                title: 'Insecure Cookie: httpOnly Flag Missing',
                explanation:
                    'A cookie is set without an options object. Express defaults httpOnly to false, ' +
                    'making the cookie readable by client-side JavaScript. If the cookie contains a ' +
                    'session token or auth credential this enables session theft via XSS.',
                threat:
                    'An XSS vulnerability in any page on the same origin can read the cookie and ' +
                    'exfiltrate the session token to an attacker-controlled server.',
                fix:
                    'Pass an options object with httpOnly: true. ' +
                    'Also set secure: true to prevent transmission over plain HTTP.',
                canonicalId: 'owlvex.issue.insecure_cookie.001',
                framework: 'OWASP',
            });
            continue;
        }

        const optionsPart = parts[2].trim();

        // If the options argument is a plain identifier (variable reference) we cannot
        // inspect its contents — skip rather than produce a false positive.
        if (/^[A-Za-z_$][A-Za-z0-9_$.]*$/.test(optionsPart)) { continue; }

        // If options is not an inline object literal we cannot analyze it — skip.
        if (!optionsPart.startsWith('{')) { continue; }

        if (!HTTPONLY_TRUE_RE.test(optionsPart)) {
            found.push({
                matchIndex: match.index,
                severity: 'MEDIUM',
                ruleCode: 'SM-001',
                title: 'Insecure Cookie: httpOnly Flag Missing',
                explanation:
                    'A cookie is set with an inline options object that does not include ' +
                    'httpOnly: true. Without this flag the cookie is readable by client-side ' +
                    'JavaScript, enabling session theft if an XSS vulnerability is present.',
                threat:
                    'An XSS vulnerability in any page on the same origin can read the cookie and ' +
                    'exfiltrate the session token to an attacker-controlled server.',
                fix:
                    'Add httpOnly: true to the options object. ' +
                    'Also set secure: true to prevent transmission over plain HTTP.',
                canonicalId: 'owlvex.issue.insecure_cookie.001',
                framework: 'OWASP',
            });
        }
    }

    return found;
}

// ==================== End SM-001 ====================

// ==================== SM-002: Debug Mode in Production ====================

/**
 * Environment context signals. If NONE of these appear in the source, the file
 * has no concept of deployment environments and the rule is silent.
 * This is the heuristic gate: we only flag debug activation in code that IS
 * env-aware — i.e., the developer could have added a guard but didn't.
 */
const DEBUG_ENV_SIGNALS = [
    'NODE_ENV', 'process.env', 'APP_ENV', 'isProduction', 'isProd',
];

// Detects `app.set('debug', true)` and `app.enable('debug')`.
const DEBUG_ACTIVATION_RE =
    /\bapp\s*\.\s*(?:set\s*\(\s*['"]debug['"]\s*,\s*true\s*\)|enable\s*\(\s*['"]debug['"]\s*\))/g;

// An env guard condition — must appear in the immediately enclosing block's condition.
const DEBUG_ENV_GUARD_CONDITION_RE =
    /\b(?:NODE_ENV|APP_ENV)\s*(?:!==?|===?)\s*['"](?:production|prod)['"]/;

/**
 * Strips block and line comments from `source`, replacing them with
 * equal-length whitespace (newlines preserved inside block comments).
 *
 * Use this for PATTERN MATCHING so that JSDoc examples containing code
 * snippets do not produce false-positive matches. String literals in code
 * are preserved so the regex can still find patterns like `app.set('debug', true)`.
 */
function stripComments(source: string): string {
    let result = source.replace(/\/\*[\s\S]*?\*\//g,
        m => m.split('').map(c => (c === '\n' ? '\n' : ' ')).join(''));
    result = result.replace(/\/\/[^\n]*/g, m => ' '.repeat(m.length));
    return result;
}

/**
 * Strips single- and double-quoted string literals from `source`.
 *
 * Apply to a comment-stripped string before using it for BRACE DEPTH TRACKING
 * so that `{` / `}` characters inside string values do not confuse the
 * depth counter in `isInsideEnvGuard`.
 */
function stripQuotedStrings(source: string): string {
    return source.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g,
        m => ' '.repeat(m.length));
}

/**
 * Returns true when `matchIndex` lies inside a block whose opening `{` is
 * preceded by an env guard condition (e.g., `NODE_ENV !== 'production'`).
 *
 * Algorithm: walk backwards through `strippedSource` (braces in string literals
 * already neutralised), tracking brace depth. The first `{` encountered at
 * depth 0 is the immediately enclosing block opener. Inspect the 300 chars of
 * original source before that `{` for a guard condition.
 */
function isInsideEnvGuard(source: string, strippedSource: string, matchIndex: number): boolean {
    let depth = 0;
    for (let i = matchIndex - 1; i >= 0; i--) {
        const ch = strippedSource[i];
        if (ch === '}') {
            depth++;
        } else if (ch === '{') {
            if (depth === 0) {
                // This is the opening brace of the immediately enclosing block.
                const before = source.slice(Math.max(0, i - 300), i);
                return DEBUG_ENV_GUARD_CONDITION_RE.test(before);
            }
            depth--;
        }
    }
    // Reached the start of the file — the call is at module top level, not guarded.
    return false;
}

function scanDebugModeSinks(source: string): InternalFinding[] {
    // Heuristic gate — only scan when the source shows deployment-env awareness.
    if (!DEBUG_ENV_SIGNALS.some(s => source.includes(s))) { return []; }

    const found: InternalFinding[] = [];
    // Two stripped views — positions are preserved 1:1 relative to `source`.
    // strippedComments: used for PATTERN MATCHING — removes JSDoc examples,
    //   but keeps string literals so `'debug'` in app.set() still matches.
    // strippedFull: used for BRACE DEPTH TRACKING — also strips string literals
    //   so `{` / `}` inside strings don't confuse the depth counter.
    const strippedComments = stripComments(source);
    const strippedFull = stripQuotedStrings(strippedComments);
    const pattern = new RegExp(DEBUG_ACTIVATION_RE.source, DEBUG_ACTIVATION_RE.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(strippedComments)) !== null) {
        if (isInsideEnvGuard(source, strippedFull, match.index)) { continue; }

        found.push({
            matchIndex: match.index,
            severity: 'MEDIUM',
            ruleCode: 'SM-002',
            title: 'Debug Mode Active Without Production Guard',
            explanation:
                `A debug activation call appears at a call site that is not enclosed by ` +
                `a \`NODE_ENV !== 'production'\` guard. ` +
                `Because this file references deployment environment signals, it is intended ` +
                `to run across environments — and debug mode will be active in all of them, ` +
                `including production.`,
            threat:
                'With debug mode active, the framework emits detailed stack traces, internal ' +
                'error state, route listings, and middleware metadata in HTTP responses and logs. ' +
                'An attacker can use this information to identify vulnerable code paths, ' +
                'enumerate hidden API endpoints, fingerprint dependencies, and construct ' +
                'targeted exploits based on precise implementation details.',
            fix:
                `Wrap the call in a production guard: ` +
                `\`if (process.env.NODE_ENV !== 'production') { /* debug activation */ }\`. ` +
                `Verify that \`NODE_ENV\` is explicitly set to \`'production'\` in all ` +
                `production deployment configurations — omitting it does not default to production.`,
            canonicalId: 'owlvex.issue.debug_mode_production.001',
            framework: 'OWASP',
        });
    }

    return found;
}

// ==================== End SM-002 ====================

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

function collectSanitizedVariables(source: string): Set<string> {
    const sanitized = new Set<string>();
    const pattern = new RegExp(SANITIZER_ASSIGN_PATTERN.source, SANITIZER_ASSIGN_PATTERN.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(source)) !== null) {
        sanitized.add(match[1]);
    }

    return sanitized;
}

function templateContainsHtmlSanitizer(templateBody: string, sanitizedVars: Set<string>): boolean {
    if (HTML_SANITIZERS.some(fn => new RegExp(String.raw`\$\{\s*${fn}\s*\(`).test(templateBody))) {
        return true;
    }

    for (const variable of sanitizedVars) {
        const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp(String.raw`\$\{\s*${escapedVariable}\s*\}`).test(templateBody)) {
            return true;
        }
    }

    return false;
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
                `The call to \`${match[1]}\` receives a template literal containing an ` +
                `interpolated expression. The interpolated value is embedded directly into ` +
                `the command string — there is no escaping layer between the value and the ` +
                `shell parser.`,
            threat:
                'An attacker who controls any interpolated value — through a URL parameter, ' +
                'request body field, HTTP header, or configuration source — can inject shell ' +
                'metacharacters (`;`, `&&`, `|`) to execute arbitrary operating system commands ' +
                'with the full privileges of the server process.',
            fix:
                'Replace the template literal with `child_process.execFile(command, [arg1, arg2])` ' +
                'and pass user-supplied values as separate array elements. ' +
                '`execFile` invokes the binary directly without a shell — metacharacters in arguments ' +
                'are treated as literal data, not shell syntax.',
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
            title: 'SQL Injection — Ineffective Sanitizer (Context Mismatch)',
            explanation:
                `A value has been processed through an HTML-oriented sanitizer ` +
                `(e.g., \`escapeHtml\`, \`htmlspecialchars\`) and is then interpolated into ` +
                `SQL query text passed to \`.${sinkName}\`. ` +
                `HTML encoding encodes characters such as \`<\` and \`>\` — it does not ` +
                `neutralise SQL metacharacters such as \`'\`, \`"\`, or \`;\`.`,
            threat:
                'The false sense of security from the HTML sanitizer leaves the query ' +
                'fully injectable. An attacker can bypass authentication, read or exfiltrate ' +
                'data from any table the database user can access, and in some configurations ' +
                'execute operating-system commands through the database engine.',
            fix:
                'Remove the HTML sanitizer from the SQL code path — it provides no protection ' +
                `here. Replace the interpolated query with a parameterized form: ` +
                `\`.${sinkName}('SELECT ... WHERE id = ?', [value])\`. ` +
                'The database driver handles safe binding; the value never becomes part of the SQL text.',
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
            `A template literal with an interpolated expression is passed directly to ` +
            `\`.${sinkName}\`. The interpolated value is embedded into the raw SQL text — ` +
            `there is no parameterization layer between the value and the SQL parser.`,
        threat:
            'An attacker who controls the interpolated value can inject SQL metacharacters ' +
            "(`'`, `\"`, `--`, `;`) to break out of the intended query structure, read or " +
            'modify any data the database user can access, bypass authentication logic, ' +
            'and in some database configurations execute operating-system commands.',
        fix:
            `Replace the template literal with a parameterized query: ` +
            `\`.${sinkName}('SELECT ... WHERE id = ?', [value])\`. ` +
            'Pass user-supplied values as bound parameters — the database driver handles ' +
            'escaping, and the value never becomes part of the SQL text.',
        canonicalId: 'owlvex.issue.sql_injection.001',
        framework: 'OWASP',
    };
}

function scanSqlSinks(source: string): InternalFinding[] {
    const found: InternalFinding[] = [];
    const sanitizedVars = collectSanitizedVariables(source);

    // Collect template literal assignments: `const query = \`SELECT ${x}\``
    const templateVars = new Map<string, boolean>();
    const assignPattern = new RegExp(TEMPLATE_ASSIGN_PATTERN.source, TEMPLATE_ASSIGN_PATTERN.flags);
    let match: RegExpExecArray | null;
    while ((match = assignPattern.exec(source)) !== null) {
        templateVars.set(match[1], templateContainsHtmlSanitizer(match[2], sanitizedVars));
    }

    // Case A: inline template literal passed directly to the sink.
    const inlinePattern = new RegExp(SQL_SINK_INLINE_PATTERN.source, SQL_SINK_INLINE_PATTERN.flags);
    while ((match = inlinePattern.exec(source)) !== null) {
        found.push(makeSqlFinding(
            match.index,
            templateContainsHtmlSanitizer(match[2], sanitizedVars),
            match[1],
        ));
    }

    // Case B: variable previously assigned a template literal passed to the sink.
    const varPattern = new RegExp(SQL_SINK_VAR_PATTERN.source, SQL_SINK_VAR_PATTERN.flags);
    while ((match = varPattern.exec(source)) !== null) {
        const varName = match[2];
        if (templateVars.has(varName)) {
            found.push(makeSqlFinding(match.index, templateVars.get(varName) === true, match[1]));
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
            ...scanIdorSinks(source),
            ...scanTenantIsolationSinks(source),
            ...scanPiiLoggingSinks(source),
            ...scanInsecureCookieSinks(source),
            ...scanDebugModeSinks(source),
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
