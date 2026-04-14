import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const strict = process.argv.includes('--strict');

const issuePackPath = path.join(repoRoot, 'docs', 'data', 'issues', 'owlvex-issue-pack.v1.json');
const issueMappingPath = path.join(repoRoot, 'docs', 'data', 'issues', 'owlvex-issue-mappings.v1.json');
const remediationPackPath = path.join(repoRoot, 'docs', 'data', 'remediation', 'owlvex-remediation-pack.v1.json');

function isValidProvenance(value) {
    return value
        && typeof value === 'object'
        && typeof value.source_type === 'string'
        && typeof value.curation_method === 'string'
        && typeof value.review_status === 'string'
        && Array.isArray(value.sources)
        && value.sources.length > 0;
}

function summarizeMissing(kind, id, field = 'provenance') {
    return `${kind} ${id}: missing ${field}`;
}

function hasNonEmptyStrings(values) {
    return Array.isArray(values) && values.length > 0 && values.every((value) => typeof value === 'string' && value.trim().length > 0);
}

function isValidFrameworkVariant(value) {
    return value
        && typeof value === 'object'
        && typeof value.framework === 'string'
        && value.framework.trim().length > 0
        && typeof value.summary === 'string'
        && value.summary.trim().length > 0
        && hasNonEmptyStrings(value.recommended_actions);
}

function isValidReference(value) {
    return value
        && typeof value === 'object'
        && typeof value.label === 'string'
        && value.label.trim().length > 0
        && typeof value.kind === 'string'
        && value.kind.trim().length > 0;
}

async function readJson(jsonPath) {
    return JSON.parse(await fs.readFile(jsonPath, 'utf8'));
}

async function main() {
    const issues = await readJson(issuePackPath);
    const mappings = await readJson(issueMappingPath);
    const remediationPack = await readJson(remediationPackPath);
    const problems = [];

    for (const issue of issues.issues ?? []) {
        if (!isValidProvenance(issue.provenance)) {
            problems.push(summarizeMissing('issue', issue.id));
        }
    }

    for (const mapping of mappings.mappings ?? []) {
        if (!isValidProvenance(mapping.provenance)) {
            problems.push(summarizeMissing('mapping', mapping.issue_id));
        }
    }

    for (const entry of remediationPack.entries ?? []) {
        if (!isValidProvenance(entry.provenance)) {
            problems.push(summarizeMissing('remediation', entry.id));
        }
        if (typeof entry.canonical_fix_summary !== 'string' || entry.canonical_fix_summary.trim().length === 0) {
            problems.push(summarizeMissing('remediation', entry.id, 'canonical_fix_summary'));
        }
        if (!Array.isArray(entry.framework_variants) || entry.framework_variants.length === 0 || !entry.framework_variants.every(isValidFrameworkVariant)) {
            problems.push(summarizeMissing('remediation', entry.id, 'framework_variants'));
        }
        if (!hasNonEmptyStrings(entry.validation_steps)) {
            problems.push(summarizeMissing('remediation', entry.id, 'validation_steps'));
        }
        if (!hasNonEmptyStrings(entry.unsafe_alternatives)) {
            problems.push(summarizeMissing('remediation', entry.id, 'unsafe_alternatives'));
        }
        if (!Array.isArray(entry.references) || entry.references.length === 0 || !entry.references.every(isValidReference)) {
            problems.push(summarizeMissing('remediation', entry.id, 'references'));
        }
    }

    if (!problems.length) {
        console.log('Grounded data provenance validation passed.');
        return;
    }

    console.log(`Grounded data provenance validation found ${problems.length} issue(s):`);
    for (const problem of problems.slice(0, 50)) {
        console.log(`- ${problem}`);
    }
    if (problems.length > 50) {
        console.log(`- ...and ${problems.length - 50} more`);
    }

    if (strict) {
        process.exitCode = 1;
    }
}

await main();
