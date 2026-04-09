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
            if (/\bsanitize\s*\(/i.test(source) || /\bsafe[A-Z][A-Za-z0-9_]*\b/.test(source)) {
                score -= 45;
                matchedSignals.push('NEG:sanitized-input');
            }
            if (/const\s+safe[A-Z][A-Za-z0-9_]*\s*=\s*sanitize\s*\(/i.test(source)) {
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
        case 'owlvex.issue.weak_jwt_validation.001':
            if (/ignoreExpiration\s*:\s*true/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:ignore-expiration');
            }
            break;
        case 'owlvex.issue.weak_auth_policy.001':
            if (/(minLength\s*[:=]\s*[0-7]\b|password\.length\s*(<|>=|>)\s*[0-7]\b|requireSpecial\s*[:=]\s*false)/i.test(source)) {
                score += 45;
                matchedSignals.push('PATTERN:weak-password-policy');
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
                (/(console\.log|logger\.(info|warn|error))/i.test(source) && /(authorization|token|password|secret|error\.message)/i.test(source))
                || (/res\.send/i.test(source) && /(authorization|token|password|secret)/i.test(source))
            ) {
                score += 40;
                matchedSignals.push('PATTERN:sensitive-log-or-response');
            }
            break;
        case 'owlvex.issue.verbose_error_disclosure.001':
            if (/(error\.message|stack)/i.test(source) && /(res\.status|res\.send|return)/i.test(source)) {
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

export function detectIssuesFromSource(source: string): DetectedIssue[] {
    let detected = ISSUE_CATALOG
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

    const hasVerboseError = detected.some(result => result.issue.id === 'owlvex.issue.verbose_error_disclosure.001');
    const hasOnlyResponseErrorPattern = /res\.send\s*\(\s*error\.message\s*\)/i.test(source)
        && !/(console\.log|logger\.(info|warn|error))/i.test(source);
    if (hasVerboseError && hasOnlyResponseErrorPattern) {
        detected = detected.filter(result => result.issue.id !== 'owlvex.issue.sensitive_logging.001');
    }

    return detected;
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
