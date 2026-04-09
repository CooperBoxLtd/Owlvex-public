import fs from 'fs';
import path from 'path';

import { CanonicalIssue, ISSUE_CATALOG, getIssueFamilyDefinition } from './issueCatalog';

type CorpusCase = {
    file: string;
    expectedCanonical: string[];
    expectedFamily: string | null;
    expectedFamilies?: string[];
    difficulty?: 'easy' | 'medium' | 'hard';
};

type CorpusManifest = {
    schema_version: string;
    title: string;
    version: string;
    cases: CorpusCase[];
};

type DetectedIssue = {
    issue: CanonicalIssue;
    matchedSignals: string[];
    score: number;
};

type DetectionContext = {
    source: string;
    withoutComments: string;
    executableSource: string;
    sanitizedVariables: string[];
    interpolatedVariables: string[];
};

type CaseEvaluation = {
    file: string;
    familyBucket: string;
    difficulty: 'easy' | 'medium' | 'hard';
    expectedCanonical: string[];
    detectedCanonical: string[];
    missedCanonical: string[];
    extraCanonical: string[];
    expectedFamily: string | null;
    expectedFamilies: string[];
    detectedFamilies: string[];
    issueCorrect: boolean;
    familyCorrect: boolean;
    falsePositive: boolean;
};

export type FamilySummary = {
    total: number;
    issueCorrect: number;
    familyCorrect: number;
    falsePositives: number;
    issueAccuracy: number;
    familyAccuracy: number;
};

export type CorpusSummary = {
    total: number;
    issueAccuracy: number;
    familyAccuracy: number;
    falsePositives: number;
    byFamily: Record<string, FamilySummary>;
    byDifficulty: Record<string, FamilySummary>;
    cases: CaseEvaluation[];
};

function normalizeExpectedFamilies(testCase: CorpusCase): string[] {
    if (testCase.expectedFamilies?.length) {
        return [...new Set(testCase.expectedFamilies)];
    }
    return testCase.expectedFamily ? [testCase.expectedFamily] : [];
}

function toPercent(value: number, total: number): number {
    return total > 0 ? Math.round((value / total) * 100) : 0;
}

function sameSet(left: string[], right: string[]): boolean {
    const a = [...new Set(left)].sort();
    const b = [...new Set(right)].sort();
    return a.length === b.length && a.every((value, index) => value === b[index]);
}

function guessFamilyIdFromPath(relativePath: string): string {
    const root = relativePath.split(/[\\/]/)[0];
    return `family.${root}`;
}

function normalizeDifficulty(value?: string): 'easy' | 'medium' | 'hard' {
    return value === 'medium' || value === 'hard' ? value : 'easy';
}

function stripComments(source: string): string {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '');
}

function stripStringLiterals(source: string): string {
    return source
        .replace(/`(?:\\.|[^`\\])*`/g, '``')
        .replace(/"(?:\\.|[^"\\])*"/g, '""')
        .replace(/'(?:\\.|[^'\\])*'/g, "''");
}

function buildDetectionContext(source: string): DetectionContext {
    const withoutComments = stripComments(source);
    return {
        source,
        withoutComments,
        executableSource: stripStringLiterals(withoutComments),
        sanitizedVariables: extractSanitizedVariables(withoutComments),
        interpolatedVariables: extractInterpolatedVariables(withoutComments),
    };
}

function extractSanitizedVariables(source: string): string[] {
    const sanitizerFunctions = new Set([
        'sanitize',
        ...[...source.matchAll(/\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*{\s*return\s+sanitize\s*\(\s*\2\s*\)\s*;?\s*}/g)]
            .map(match => match[1]),
        ...[...source.matchAll(/\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*=>\s*sanitize\s*\(\s*\2\s*\)\s*;?/g)]
            .map(match => match[1]),
    ]);

    const safeVariables = new Set<string>();
    const assignmentPattern = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$/;
    const lines = source.split(/\r?\n/);
    let conditionalDepth = 0;

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) {
            continue;
        }

        const normalized = trimmed.replace(/^}+\s*/, '');
        const startsConditional = /^(if|else\s+if|else|switch|case)\b/.test(normalized);
        const opens = (normalized.match(/{/g) ?? []).length;
        const closes = (normalized.match(/}/g) ?? []).length;

        const assignment = trimmed.match(assignmentPattern);
        if (assignment && conditionalDepth === 0 && !startsConditional) {
            const [, variable, rawValue] = assignment;
            const value = rawValue.trim();
            const sanitizeCall = value.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/);
            const aliasMatch = value.match(/^([A-Za-z_$][A-Za-z0-9_$]*)$/);

            if (sanitizeCall && sanitizerFunctions.has(sanitizeCall[1])) {
                safeVariables.add(variable);
            } else if (aliasMatch && safeVariables.has(aliasMatch[1])) {
                safeVariables.add(variable);
            } else {
                safeVariables.delete(variable);
            }
        }

        if (startsConditional) {
            conditionalDepth += Math.max(1, opens);
        } else if (conditionalDepth > 0) {
            conditionalDepth += opens;
        }

        if (conditionalDepth > 0) {
            conditionalDepth -= closes;
        }
        conditionalDepth = Math.max(0, conditionalDepth);
    }

    return [...safeVariables];
}

function extractInterpolatedVariables(source: string): string[] {
    const templateMatches = [...source.matchAll(/\$\{\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\}/g)].map(match => match[1]);
    const concatMatches = [...source.matchAll(/['"]\s*\+\s*([A-Za-z_$][A-Za-z0-9_$]*)/g)].map(match => match[1]);
    return [...new Set([...templateMatches, ...concatMatches])];
}

function hasErrorLikeMessage(source: string): boolean {
    return /\b[A-Za-z_$][A-Za-z0-9_$]*\.(message|stack)\b/i.test(source);
}

function hasAuthGuard(source: string): boolean {
    return /\b(requireAuth|authenticate|ensureAuthenticated|authMiddleware|jwt\.verify|isAuthenticated|req\.user)\b/i.test(source);
}

function hasPrivilegeGuard(source: string): boolean {
    return /\b(requireAdmin|requireRole|authorizeAdmin|policy\.enforce|req\.user\.role\s*===\s*['"]admin['"])\b/i.test(source);
}

function hasPrivilegedAction(source: string): boolean {
    return /\b(delete|post|put|patch)\b/i.test(source)
        || /\b(deleteUser|removeUser|grantRole|revokeRole|exportData|manageUsers)\b/i.test(source);
}

function buildSourceSignals(source: string, issue: CanonicalIssue): { score: number; matchedSignals: string[] } {
    const haystack = source.toLowerCase();
    let score = 0;
    const matchedSignals: string[] = [];

    for (const keyword of issue.keywords) {
        if (haystack.includes(keyword.toLowerCase())) {
            score += 15;
            matchedSignals.push(keyword);
        }
    }

    const requiredKeywordHit = !issue.requiredAnyKeywords?.length
        || issue.requiredAnyKeywords.some(keyword => haystack.includes(keyword.toLowerCase()));
    if (!requiredKeywordHit) {
        score -= 80;
    }

    for (const keyword of issue.negativeKeywords ?? []) {
        if (haystack.includes(keyword.toLowerCase())) {
            score -= 35;
            matchedSignals.push(`NEG:${keyword}`);
        }
    }

    const stringLiteralAssignment = /\b(const|let|var)\s+[A-Za-z0-9_$]+\s*=\s*['"][^'"]{4,}['"]/i.test(source);
    const templateLiteralInterpolation = /`[^`]*\$\{[^}]+}[^`]*`/s.test(source);

    switch (issue.id) {
        case 'owlvex.issue.hardcoded_api_key.001':
            if (/\b(apiKey|api_key|apikey|clientSecret|accessKey)\b/i.test(source) && stringLiteralAssignment) {
                score += 45;
                matchedSignals.push('PATTERN:hardcoded-api-key');
            }
            break;
        case 'owlvex.issue.hardcoded_password.001':
            if (/\b(password|dbPassword|passwd|pwd)\b/i.test(source) && stringLiteralAssignment) {
                score += 45;
                matchedSignals.push('PATTERN:hardcoded-password');
            }
            break;
        case 'owlvex.issue.hardcoded_token.001':
            if (/\b(token|authToken|bearerToken|refreshToken|jwtSecret)\b/i.test(source) && stringLiteralAssignment) {
                score += 45;
                matchedSignals.push('PATTERN:hardcoded-token');
            }
            if (/(placeholder|todo|demo token|process\.env\.[A-Z0-9_]+)/i.test(source)) {
                score -= 50;
                matchedSignals.push('NEG:placeholder-or-env-reference');
            }
            break;
        case 'owlvex.issue.hardcoded_secret.001':
            if (/\b(secret|privateKey|signingKey)\b/i.test(source) && stringLiteralAssignment) {
                score += 45;
                matchedSignals.push('PATTERN:hardcoded-secret');
            }
            break;
        case 'owlvex.issue.sql_injection.001':
            const hasSqlSink = /\b(select|update|insert|delete)\b/i.test(source) && /\bquery\s*\(/i.test(source);
            const hasQueryInterpolation = templateLiteralInterpolation || /'\s*\+\s*[A-Za-z0-9_$]+/.test(source);
            const safeVariables = extractSanitizedVariables(source);
            const interpolatedVariables = extractInterpolatedVariables(source);
            const hasUnsafeInterpolation = interpolatedVariables.some(variable => !safeVariables.includes(variable));
            const hasOnlySafeInterpolation = interpolatedVariables.length > 0 && !hasUnsafeInterpolation;
            if (hasSqlSink) {
                score += 15;
                matchedSignals.push('PATTERN:sql-sink');
            }
            if (hasQueryInterpolation) {
                score += 20;
                matchedSignals.push('PATTERN:query-interpolation');
            }
            if (/\?\s*['"`]?\s*,\s*\[[^\]]+\]/.test(source) || /query\s*\([^)]*\[[^\]]+\]\)/i.test(source)) {
                score -= 35;
                matchedSignals.push('NEG:parameter-array');
            }
            if (/where\s+[a-z0-9_]+\s*=\s*\?/i.test(source)) {
                score -= 25;
                matchedSignals.push('NEG:sql-placeholder');
            }
            if (hasOnlySafeInterpolation || (!hasUnsafeInterpolation && (/\bsanitize\s*\(/i.test(source) || /\bsafe[A-Z][A-Za-z0-9_]*\b/.test(source)))) {
                score -= 45;
                matchedSignals.push('NEG:sanitized-input');
            }
            if (hasOnlySafeInterpolation && /const\s+safe[A-Z][A-Za-z0-9_]*\s*=\s*sanitize\s*\(/i.test(source)) {
                score -= 30;
                matchedSignals.push('NEG:sanitized-assignment');
            }
            break;
        case 'owlvex.issue.command_injection.001':
            if (/\bexec\s*\(/i.test(source)) {
                score += 35;
                matchedSignals.push('PATTERN:exec-sink');
            }
            if (templateLiteralInterpolation || /'\s*\+\s*[A-Za-z0-9_$]+/.test(source)) {
                score += 20;
                matchedSignals.push('PATTERN:command-interpolation');
            }
            break;
        case 'owlvex.issue.code_injection.eval.001':
            if (/\b(eval\s*\(|new\s+Function\s*\()/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:dynamic-code-sink');
            }
            if (/\b(req\.(body|query|params)|userInput|input|payload|expression)\b/i.test(source)) {
                score += 20;
                matchedSignals.push('PATTERN:untrusted-code-input');
            }
            if (/\beval\s*\(\s*['"`][^'"`]+['"`]\s*\)/i.test(source)) {
                score -= 40;
                matchedSignals.push('NEG:static-expression');
            }
            break;
        case 'owlvex.issue.nosql_injection.001':
            if (
                /\$(where|ne|regex)\b/i.test(source)
                || /\bfind\s*\(\s*(req\.|filter\b|query\b|criteria\b)/i.test(source)
            ) {
                score += 40;
                matchedSignals.push('PATTERN:nosql-operator');
            }
            break;
        case 'owlvex.issue.template_injection.001':
            if (
                /\{\{.*\}\}/s.test(source)
                || /\brender\s*\(\s*(req\.|tpl\b|template\b)/i.test(source)
                || /\bengine\.render\s*\(\s*(tpl\b|template\b)/i.test(source)
            ) {
                score += 40;
                matchedSignals.push('PATTERN:template-expression');
            }
            break;
        case 'owlvex.issue.insecure_deserialization.001':
            if (
                /\b(yaml\.load|deserialize\s*\(|unserialize\s*\(|pickle\.loads|BinaryFormatter|ObjectInputStream)\b/i.test(source)
                && /\b(req\.(body|query|params)|userInput|input|payload|body)\b/i.test(source)
            ) {
                score += 45;
                matchedSignals.push('PATTERN:unsafe-deserializer');
            }
            break;
        case 'owlvex.issue.missing_authentication_check.001':
            if (
                /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]\/(admin|internal|billing|account|settings|users)\b/i.test(source)
                && !hasAuthGuard(source)
                && !hasPrivilegeGuard(source)
            ) {
                score += 50;
                matchedSignals.push('PATTERN:protected-route-without-auth');
            }
            break;
        case 'owlvex.issue.weak_jwt_validation.001':
            if (/ignoreExpiration\s*:\s*true/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:ignore-expiration');
            }
            if (/\bjwt\.decode\s*\(/i.test(source) && !/\bjwt\.verify\s*\(/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:decode-without-verify');
            }
            break;
        case 'owlvex.issue.weak_auth_policy.001':
            if (/(minLength\s*[:=]\s*[0-7]\b|password\.length\s*(<|>=|>)\s*[0-7]\b|requireSpecial\s*[:=]\s*false)/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:weak-password-policy');
            }
            break;
        case 'owlvex.issue.broken_function_level_authorization.001':
            if (
                /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]\/(admin|delete|export|manage|users)\b/i.test(source)
                && /\b(req\.user|isAuthenticated|authenticate)\b/i.test(source)
                && hasPrivilegedAction(source)
                && !hasPrivilegeGuard(source)
            ) {
                score += 50;
                matchedSignals.push('PATTERN:privileged-route-without-authorization');
            }
            break;
        case 'owlvex.issue.idor.001':
            if (
                /\b(req\.params\.(id|userId|accountId)|params\.(id|userId|accountId)|userId|accountId)\b/i.test(source)
                && /(findByPk|getById|findOne|where\s*:\s*{?\s*id|where id = \?|select \* from)/i.test(source)
                && !/\b(account_id|owner_id|req\.user|authorization|policy\.enforce)\b/i.test(source)
            ) {
                score += 40;
                matchedSignals.push('PATTERN:unscoped-object-access');
            }
            if (
                /\bisAuthenticated\b/i.test(source)
                && /\bquery\s*\(/i.test(source)
                && /\breq\.params\.(id|userId|accountId)\b/i.test(source)
                && !/\b(req\.user\.(id|accountId)|owner_id|account_id|forbidden|policy\.enforce)\b/i.test(source)
            ) {
                score += 50;
                matchedSignals.push('PATTERN:authenticated-not-authorized');
            }
            if (
                /\breq\.user(\.role)?\b/i.test(source)
                && /\bquery\s*\(/i.test(source)
                && /\breq\.params\.(id|userId|accountId)\b/i.test(source)
                && !/\b(req\.user\.(id|accountId)|owner_id|account_id|forbidden|policy\.enforce)\b/i.test(source)
            ) {
                score += 45;
                matchedSignals.push('PATTERN:auth-present-no-ownership-check');
            }
            break;
        case 'owlvex.issue.path_traversal.001':
            if (
                /(\.\.\/|path\.join\([^)]*(requested|input|filename|filePath)|readFile(Sync)?\([^)]*(requested|input|filename|filePath)|open\([^)]*(requested|input|filename|filePath))/i.test(source)
            ) {
                score += 40;
                matchedSignals.push('PATTERN:path-traversal');
            }
            break;
        case 'owlvex.issue.sensitive_logging.001':
            if (
                (/(console\.log|logger\.(info|warn|error))/i.test(source) && (/(authorization|token|password|secret)/i.test(source) || hasErrorLikeMessage(source)))
                || (/res\.send/i.test(source) && /(authorization|token|password|secret)/i.test(source))
            ) {
                score += 40;
                matchedSignals.push('PATTERN:sensitive-log-or-response');
            }
            break;
        case 'owlvex.issue.verbose_error_disclosure.001':
            if (hasErrorLikeMessage(source) && /(res\.status|res\.send|return)/i.test(source)) {
                score += 40;
                matchedSignals.push('PATTERN:verbose-error');
            }
            break;
        case 'owlvex.issue.weak_crypto.001':
            if (/\b(md5|sha1|des|rc4)\b/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:weak-crypto');
            }
            break;
        default:
            break;
    }

    return { score, matchedSignals: [...new Set(matchedSignals)] };
}

function buildRawDetectionsFromSource(source: string): DetectedIssue[] {
    return ISSUE_CATALOG
        .map(issue => {
            const result = buildSourceSignals(source, issue);
            return {
                issue,
                matchedSignals: result.matchedSignals,
                score: result.score,
            };
        })
        .filter(result => result.score >= (result.issue.minimumScore ?? 25))
        .sort((left, right) => right.score - left.score);
}

function hasExecutablePattern(context: DetectionContext, pattern: RegExp): boolean {
    return pattern.test(context.executableSource);
}

function applyNoiseSuppression(detections: DetectedIssue[], context: DetectionContext): DetectedIssue[] {
    return detections.filter(detection => {
        switch (detection.issue.id) {
            case 'owlvex.issue.hardcoded_token.001':
                if (!detection.matchedSignals.includes('PATTERN:hardcoded-token')) {
                    return false;
                }
                if (/authorization:\s*bearer\s*<token>/i.test(context.withoutComments)) {
                    return false;
                }
                return true;
            default:
                return true;
        }
    });
}

function applyExecutionGuards(detections: DetectedIssue[], context: DetectionContext): DetectedIssue[] {
    return detections.filter(detection => {
        switch (detection.issue.id) {
            case 'owlvex.issue.sql_injection.001':
                if (!hasExecutablePattern(context, /\bquery\s*\(/i)) {
                    return false;
                }
                if (/\bif\s*\(\s*false\s*\)\s*{[\s\S]*\bquery\s*\(/i.test(context.withoutComments)) {
                    return false;
                }
                if (context.interpolatedVariables.length === 0) {
                    return true;
                }
                const unsafeVariables = context.interpolatedVariables.filter(variable => !context.sanitizedVariables.includes(variable));
                return unsafeVariables.length > 0;
            case 'owlvex.issue.command_injection.001':
                return hasExecutablePattern(context, /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/i);
            case 'owlvex.issue.code_injection.eval.001':
                return hasExecutablePattern(context, /\b(eval\s*\(|new\s+Function\s*\()/i)
                    && /\b(req\.(body|query|params)|userInput|input|payload|expression)\b/i.test(context.withoutComments);
            case 'owlvex.issue.insecure_deserialization.001':
                return hasExecutablePattern(context, /\b(yaml\.load|deserialize\s*\(|unserialize\s*\(|pickle\.loads|BinaryFormatter|ObjectInputStream)\b/i);
            case 'owlvex.issue.missing_authentication_check.001':
                return !hasAuthGuard(context.withoutComments) && !hasPrivilegeGuard(context.withoutComments);
            case 'owlvex.issue.broken_function_level_authorization.001':
                return /\b(req\.user|isAuthenticated|authenticate)\b/i.test(context.withoutComments)
                    && hasPrivilegedAction(context.withoutComments)
                    && !hasPrivilegeGuard(context.withoutComments);
            case 'owlvex.issue.verbose_error_disclosure.001':
                return hasExecutablePattern(context, /(res\.(status|send|json)|return)\s*\(?[^;\n]*\b[A-Za-z_$][A-Za-z0-9_$]*\.(message|stack)\b/i);
            case 'owlvex.issue.sensitive_logging.001':
                return hasExecutablePattern(context, /(console\.log|logger\.(info|warn|error)|res\.send)\s*\(/i)
                    && (/(authorization|token|password|secret)/i.test(context.withoutComments) || hasErrorLikeMessage(context.withoutComments));
            default:
                return true;
        }
    });
}

function applyFamilyDisambiguation(detections: DetectedIssue[], context: DetectionContext): DetectedIssue[] {
    const hasVerboseError = detections.some(result => result.issue.id === 'owlvex.issue.verbose_error_disclosure.001');
    const hasOnlyResponseErrorPattern = /res\.send\s*\([^;\n]*[A-Za-z_$][A-Za-z0-9_$]*\.message/i.test(context.withoutComments)
        && !/(console\.log|logger\.(info|warn|error))/i.test(context.withoutComments);
    if (hasVerboseError && hasOnlyResponseErrorPattern) {
        return detections.filter(result => result.issue.id !== 'owlvex.issue.sensitive_logging.001');
    }
    return detections;
}

function resolveConflicts(detections: DetectedIssue[], source: string): DetectedIssue[] {
    const context = buildDetectionContext(source);
    let resolved = [...detections];

    resolved = applyNoiseSuppression(resolved, context);
    resolved = applyExecutionGuards(resolved, context);
    resolved = applyFamilyDisambiguation(resolved, context);

    return resolved.sort((left, right) => right.score - left.score);
}

export function detectIssuesFromSource(source: string): DetectedIssue[] {
    const rawDetections = buildRawDetectionsFromSource(source);
    return resolveConflicts(rawDetections, source);
}

export function loadCorpusManifest(repoRoot: string): CorpusManifest {
    const manifestPath = path.join(repoRoot, 'corpus', 'manifest.json');
    return JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as CorpusManifest;
}

export function evaluateCorpus(repoRoot: string): CorpusSummary {
    const manifest = loadCorpusManifest(repoRoot);
    const cases: CaseEvaluation[] = manifest.cases.map(testCase => {
        const source = fs.readFileSync(path.join(repoRoot, 'corpus', testCase.file), 'utf8');
        const detections = detectIssuesFromSource(source);
        const detectedCanonical = detections.map(result => result.issue.id);
        const detectedFamilies = [...new Set(detections.map(result => result.issue.family))];
        const expectedFamilies = normalizeExpectedFamilies(testCase);
        const familyBucket = expectedFamilies[0] ?? guessFamilyIdFromPath(testCase.file);
        const difficulty = normalizeDifficulty(testCase.difficulty);
        const missedCanonical = testCase.expectedCanonical.filter(issueId => !detectedCanonical.includes(issueId));
        const extraCanonical = detectedCanonical.filter(issueId => !testCase.expectedCanonical.includes(issueId));
        const issueCorrect = sameSet(testCase.expectedCanonical, detectedCanonical);
        const familyCorrect = expectedFamilies.length > 0
            ? sameSet(expectedFamilies, detectedFamilies)
            : detectedFamilies.length === 0;
        const falsePositive = testCase.expectedCanonical.length === 0 && detectedCanonical.length > 0;

        return {
            file: testCase.file,
            familyBucket,
            difficulty,
            expectedCanonical: testCase.expectedCanonical,
            detectedCanonical,
            missedCanonical,
            extraCanonical,
            expectedFamily: testCase.expectedFamily,
            expectedFamilies,
            detectedFamilies,
            issueCorrect,
            familyCorrect,
            falsePositive,
        };
    });

    const issueCorrectCount = cases.filter(result => result.issueCorrect).length;
    const familyCorrectCount = cases.filter(result => result.familyCorrect).length;
    const falsePositives = cases.filter(result => result.falsePositive).length;

    const grouped = new Map<string, CaseEvaluation[]>();
    for (const result of cases) {
        const entries = grouped.get(result.familyBucket) ?? [];
        entries.push(result);
        grouped.set(result.familyBucket, entries);
    }

    const byDifficulty = Object.fromEntries(
        ['easy', 'medium', 'hard'].map(difficulty => {
            const results = cases.filter(result => result.difficulty === difficulty);
            const issueCorrect = results.filter(result => result.issueCorrect).length;
            const familyCorrect = results.filter(result => result.familyCorrect).length;
            const difficultyFalsePositives = results.filter(result => result.falsePositive).length;

            return [
                difficulty,
                {
                    total: results.length,
                    issueCorrect,
                    familyCorrect,
                    falsePositives: difficultyFalsePositives,
                    issueAccuracy: toPercent(issueCorrect, results.length),
                    familyAccuracy: toPercent(familyCorrect, results.length),
                } satisfies FamilySummary,
            ];
        }),
    );

    const byFamily = Object.fromEntries(
        [...grouped.entries()].map(([familyId, results]) => {
            const issueCorrect = results.filter(result => result.issueCorrect).length;
            const familyCorrect = results.filter(result => result.familyCorrect).length;
            const familyFalsePositives = results.filter(result => result.falsePositive).length;
            const label = getIssueFamilyDefinition(familyId)?.label ?? familyId;

            return [
                label,
                {
                    total: results.length,
                    issueCorrect,
                    familyCorrect,
                    falsePositives: familyFalsePositives,
                    issueAccuracy: toPercent(issueCorrect, results.length),
                    familyAccuracy: toPercent(familyCorrect, results.length),
                } satisfies FamilySummary,
            ];
        }),
    );

    return {
        total: cases.length,
        issueAccuracy: toPercent(issueCorrectCount, cases.length),
        familyAccuracy: toPercent(familyCorrectCount, cases.length),
        falsePositives,
        byFamily,
        byDifficulty,
        cases,
    };
}

export function formatCorpusSummary(summary: CorpusSummary): string {
    const lines: string[] = [
        'Corpus results:',
        '',
        'Overall:',
        `- Total cases: ${summary.total}`,
        `- Issue accuracy: ${summary.issueAccuracy}%`,
        `- Family accuracy: ${summary.familyAccuracy}%`,
        `- False positives: ${summary.falsePositives}`,
        '',
        'By family:',
    ];

    for (const [familyLabel, metrics] of Object.entries(summary.byFamily)) {
        lines.push(`${familyLabel}:`);
        lines.push(`- Cases: ${metrics.total}`);
        lines.push(`- Issue accuracy: ${metrics.issueAccuracy}%`);
        lines.push(`- Family accuracy: ${metrics.familyAccuracy}%`);
        lines.push(`- False positives: ${metrics.falsePositives}`);
        lines.push('');
    }

    lines.push('By difficulty:');
    for (const [difficulty, metrics] of Object.entries(summary.byDifficulty)) {
        if (metrics.total === 0) {
            continue;
        }
        lines.push(`${difficulty}:`);
        lines.push(`- Cases: ${metrics.total}`);
        lines.push(`- Issue accuracy: ${metrics.issueAccuracy}%`);
        lines.push(`- Family accuracy: ${metrics.familyAccuracy}%`);
        lines.push(`- False positives: ${metrics.falsePositives}`);
        lines.push('');
    }

    return lines.join('\n').trimEnd();
}

function parseArgs(args: string[]): { jsonPath?: string } {
    const jsonIndex = args.indexOf('--json');
    if (jsonIndex >= 0 && args[jsonIndex + 1]) {
        return { jsonPath: args[jsonIndex + 1] };
    }
    return {};
}

function main(): void {
    const repoRoot = path.resolve(process.cwd(), '..');
    const options = parseArgs(process.argv.slice(2));
    const summary = evaluateCorpus(repoRoot);

    console.log(formatCorpusSummary(summary));

    if (options.jsonPath) {
        const outputPath = path.resolve(process.cwd(), options.jsonPath);
        fs.mkdirSync(path.dirname(outputPath), { recursive: true });
        fs.writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
        console.log('');
        console.log(`Wrote JSON snapshot to ${outputPath}`);
    }
}

if (require.main === module) {
    main();
}
