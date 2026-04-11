import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { repoRoot, toolRoot } from './repo-root.mjs';

const manifestPath = path.join(toolRoot, 'manifest.json');
const templatePath = path.join(toolRoot, 'results.template.json');

function runCommand(command, args, input = '') {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, { cwd: repoRoot, stdio: ['pipe', 'pipe', 'pipe'] });
        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });

        child.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });

        child.on('error', reject);
        child.on('close', (code) => {
            if (code !== 0) {
                reject(new Error(stderr.trim() || `${command} exited with code ${code}`));
                return;
            }

            resolve(stdout);
        });

        child.stdin.end(input);
    });
}

function extractJsonObject(text) {
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
        throw new Error(`Model response did not contain JSON: ${text.slice(0, 200)}`);
    }

    return JSON.parse(text.slice(firstBrace, lastBrace + 1));
}

function buildPrompt(caseDefinition, code) {
    return [
        'You are evaluating code for a security benchmark.',
        'Return JSON only with this exact shape:',
        '{"verdict":"vulnerable|clean|advisory","labels":["..."],"cwes":["..."],"findings":["short finding strings"],"notes":"short text"}',
        'Rules:',
        '- verdict vulnerable: exploitable issue is present',
        '- verdict clean: no security issue in this file',
        '- verdict advisory: behavior influences system behavior but is not a direct vulnerability',
        '- labels should be short issue names',
        '- cwes should contain CWE identifiers only when strongly justified',
        '- findings should be brief plain-English summaries',
        `Benchmark case: ${caseDefinition.id}`,
        `File: ${caseDefinition.file}`,
        'Code:',
        '```js',
        code,
        '```',
    ].join('\n');
}

function normalizeVerdict(value) {
    const verdict = String(value || '').trim().toLowerCase();
    if (['vulnerable', 'clean', 'advisory'].includes(verdict)) {
        return verdict;
    }

    if (verdict === 'informational' || verdict === 'info') {
        return 'advisory';
    }

    return 'clean';
}

async function main() {
    const host = process.argv[2] || 'cristian@192.168.50.35';
    const model = process.argv[3] || 'qwen2.5:7b';
    const outputPath = process.argv[4]
        ? path.resolve(repoRoot, process.argv[4])
        : path.join(toolRoot, 'runs', `${model.replace(/[^a-zA-Z0-9._-]/g, '_')}.results.json`);

    const [manifestRaw, templateRaw] = await Promise.all([
        fs.readFile(manifestPath, 'utf8'),
        fs.readFile(templatePath, 'utf8'),
    ]);

    const manifest = JSON.parse(manifestRaw);
    const template = JSON.parse(templateRaw);
    const cases = [];

    for (const caseDefinition of manifest.cases) {
        const code = await fs.readFile(path.resolve(repoRoot, caseDefinition.file), 'utf8');
        const responseText = await runCommand('ssh', [host, 'ollama', 'run', model], buildPrompt(caseDefinition, code));
        const parsed = extractJsonObject(responseText);

        cases.push({
            id: caseDefinition.id,
            verdict: normalizeVerdict(parsed.verdict),
            labels: Array.isArray(parsed.labels) ? parsed.labels : [],
            cwes: Array.isArray(parsed.cwes) ? parsed.cwes : [],
            findings: Array.isArray(parsed.findings) ? parsed.findings : [],
            notes: typeof parsed.notes === 'string' ? parsed.notes : '',
        });
    }

    const results = {
        ...template,
        run: {
            provider: 'ollama',
            model,
            date: new Date().toISOString().slice(0, 10),
            frameworks: ['OWASP', 'STRIDE', 'CWE', 'MITRE', 'CLEANCODE'],
            scope: 'corpus and tools/owlvex-benchmark/corpus',
            notes: `Generated over SSH via ${host}`,
        },
        cases,
    };

    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, `${JSON.stringify(results, null, 2)}\n`, 'utf8');
    console.log(`Wrote benchmark results to ${path.relative(repoRoot, outputPath)}`);
}

main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
