import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot, toolRoot } from './repo-root.mjs';

const manifestPath = path.join(toolRoot, 'manifest.json');
const resultsPath = process.argv[2]
    ? path.resolve(repoRoot, process.argv[2])
    : path.join(toolRoot, 'runs', 'latest.results.json');

function normalizeText(value) {
    return String(value || '').trim().toLowerCase();
}

function includesAny(haystacks, needles) {
    const normalizedHaystacks = haystacks.map(normalizeText);
    return needles.some((needle) => normalizedHaystacks.some((entry) => entry.includes(normalizeText(needle))));
}

function includesNone(haystacks, needles) {
    const normalizedHaystacks = haystacks.map(normalizeText);
    return needles.every((needle) => normalizedHaystacks.every((entry) => !entry.includes(normalizeText(needle))));
}

function gatherCaseText(caseResult) {
    return [
        caseResult.verdict,
        ...(caseResult.labels || []),
        ...(caseResult.cwes || []),
        ...(caseResult.findings || []),
        caseResult.notes || '',
    ].filter(Boolean);
}

function expectedVerdictMatches(expectedVerdict, actualVerdict) {
    const verdict = normalizeText(actualVerdict);
    if (expectedVerdict === 'fixed_or_advisory') {
        return ['fixed', 'advisory', 'informational', 'clean', 'none'].includes(verdict);
    }

    return normalizeText(expectedVerdict) === verdict;
}

function scoreCase(caseDefinition, caseResult) {
    const text = gatherCaseText(caseResult);
    const expected = caseDefinition.expected;
    const checks = [];

    checks.push(expectedVerdictMatches(expected.verdict, caseResult.verdict));

    if (expected.must_include) {
        checks.push(includesAny(text, expected.must_include));
    }

    if (expected.must_not_include) {
        checks.push(includesNone(text, expected.must_not_include));
    }

    if (expected.preferred_cwe) {
        checks.push(includesAny(caseResult.cwes || [], expected.preferred_cwe));
    }

    if (expected.allowed_labels) {
        const normalizedLabels = (caseResult.labels || []).map(normalizeText);
        checks.push(
            normalizedLabels.length === 0 ||
            normalizedLabels.every((label) => expected.allowed_labels.some((allowed) => normalizeText(allowed) === label)),
        );
    }

    if (typeof expected.max_findings === 'number') {
        checks.push((caseResult.findings || []).length <= expected.max_findings);
    }

    const passedChecks = checks.filter(Boolean).length;
    return {
        passed: passedChecks === checks.length,
        passedChecks,
        totalChecks: checks.length,
    };
}

async function main() {
    const [manifestRaw, resultsRaw] = await Promise.all([
        fs.readFile(manifestPath, 'utf8'),
        fs.readFile(resultsPath, 'utf8'),
    ]);

    const manifest = JSON.parse(manifestRaw);
    const results = JSON.parse(resultsRaw);

    if (manifest.suite !== results.suite) {
        throw new Error(`Suite mismatch: manifest=${manifest.suite} results=${results.suite}`);
    }

    const caseResultsById = new Map(results.cases.map((entry) => [entry.id, entry]));
    const scoredCases = [];

    for (const caseDefinition of manifest.cases) {
        const caseResult = caseResultsById.get(caseDefinition.id);
        if (!caseResult) {
            throw new Error(`Missing result for case: ${caseDefinition.id}`);
        }

        scoredCases.push({
            id: caseDefinition.id,
            file: caseDefinition.file,
            dimensions: caseDefinition.dimensions,
            ...scoreCase(caseDefinition, caseResult),
        });
    }

    const dimensionScores = Object.fromEntries(
        Object.keys(manifest.dimensions).map((dimension) => {
            const relevant = scoredCases.filter((entry) => entry.dimensions.includes(dimension));
            const passed = relevant.filter((entry) => entry.passed).length;
            const total = relevant.length;
            const weight = manifest.dimensions[dimension];
            const score = total === 0 ? 0 : Math.round((passed / total) * weight);
            return [dimension, { passed, total, weight, score }];
        }),
    );

    const totalScore = Object.values(dimensionScores).reduce((sum, entry) => sum + entry.score, 0);
    const rating =
        totalScore >= 90 ? 'strong primary model'
            : totalScore >= 75 ? 'usable with guardrails'
                : totalScore >= 60 ? 'weak on precision or remediation reasoning'
                    : 'not reliable enough for primary security judgment';

    console.log(JSON.stringify({
        run: results.run,
        totalScore,
        rating,
        dimensions: dimensionScores,
        cases: scoredCases,
    }, null, 2));
}

main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
