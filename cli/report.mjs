/**
 * report.mjs — markdown report builder for the Owlvex CLI
 *
 * No vscode dependency. Pure string generation.
 * Mirrors the attack surface assessment + deterministic detections panel
 * from the extension's reportGenerator.ts, without the AI findings section.
 */

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

function capitalize(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function sortFindings(findings) {
    return [...findings].sort((a, b) => {
        const sa = SEV_ORDER[a.severity?.toLowerCase()] ?? 5;
        const sb = SEV_ORDER[b.severity?.toLowerCase()] ?? 5;
        return sa - sb;
    });
}

// ── Attack Surface Assessment ──────────────────────────────────────────────

function buildAttackSurfaceAssessment(totalFindings, deterministicCount, scanned, filesWithFindings) {
    if (totalFindings === 0) {
        return [
            '## Attack Surface Assessment',
            '',
            `Owlvex scanned ${scanned} file${scanned !== 1 ? 's' : ''} and identified no security findings. ` +
            `The deterministic engine found no invariant violations in any of the covered categories. ` +
            `This result does not imply a clean codebase for patterns outside the engine\'s current scope.`,
            '',
        ];
    }

    const sevCounts = {};
    // Build severity summary from the raw results passed to this function
    // (already aggregated by caller)

    const detPct = totalFindings > 0 ? Math.round((deterministicCount / totalFindings) * 100) : 0;

    const immediateCount = deterministicCount; // deterministic = requires immediate attention

    const lines = [
        '## Attack Surface Assessment',
        '',
    ];

    const immediate = deterministicCount > 0
        ? ` ${deterministicCount === totalFindings ? 'All' : deterministicCount} ` +
          `finding${deterministicCount !== 1 ? 's were' : ' was'} confirmed by deterministic structural analysis — ` +
          `these are invariant violations in the code structure, not probabilistic inferences. ` +
          `Each carries 100% confidence and requires no additional validation before escalation.`
        : '';

    const para = `Owlvex identified ${totalFindings} security finding${totalFindings !== 1 ? 's' : ''} ` +
        `across ${filesWithFindings} of ${scanned} scanned file${scanned !== 1 ? 's' : ''}.${immediate}`;

    lines.push(para, '');
    return lines;
}

// ── Deterministic Detections Panel ────────────────────────────────────────

function buildDeterministicPanel(allResults) {
    const items = [];
    for (const { file, findings } of allResults) {
        for (const f of findings) {
            // All CLI findings are deterministic (DeterministicScanner only)
            if (f.ruleCode) {
                items.push({ file, ...f });
            }
        }
    }

    if (items.length === 0) return [];

    const lines = [
        '## ⚡ Deterministic Detections',
        '',
        '| Rule | Finding | File | Line | Severity |',
        '|------|---------|------|------|----------|',
    ];

    const sorted = sortFindings(items);
    for (const item of sorted) {
        const rule = `\`${item.ruleCode}\``;
        const title = item.title ?? 'Unknown';
        const file = `\`${item.file}\``;
        const line = item.line ?? '—';
        const sev = `**${capitalize(item.severity)}**`;
        lines.push(`| ⚡ ${rule} | ${title} | ${file} | ${line} | ${sev} |`);
    }

    lines.push('');
    return lines;
}

// ── Per-finding detail ─────────────────────────────────────────────────────

function buildFindingDetail(f, file) {
    const sev = capitalize(f.severity ?? 'unknown');
    // All CLI findings come from DeterministicScanner — always deterministic
    const provenance = `⚡ Deterministic (rule: ${f.ruleCode ?? '?'}) — structural invariant, confidence 100%`;

    const lines = [
        `### ${f.title ?? 'Finding'}`,
        '',
        `| Field | Value |`,
        `|-------|-------|`,
        `| **Severity** | ${sev} |`,
        `| **Rule** | ${f.ruleCode ?? '—'} |`,
        `| **File** | \`${file}\` |`,
        `| **Line** | ${f.line ?? '—'} |`,
        `| **Provenance** | ${provenance} |`,
        '',
    ];

    if (f.explanation) {
        lines.push(f.explanation, '');
    }

    if (f.fix) {
        lines.push('**Recommendation:**', '', f.fix, '');
    }

    if (f.codeSnippet) {
        lines.push('```javascript', f.codeSnippet, '```', '');
    }

    return lines;
}

// ── Main report builder ────────────────────────────────────────────────────

export function buildMarkdownReport({ rootDir, scanned, results }) {
    const totalFindings = results.reduce((n, r) => n + r.findings.length, 0);
    // All findings from DeterministicScanner have a ruleCode — all are deterministic
    const deterministicCount = totalFindings;
    const filesWithFindings = results.length;

    const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    const lines = [
        '# Owlvex Security Report',
        '',
        `**Scan target:** \`${rootDir}\`  `,
        `**Generated:** ${now}  `,
        `**Files scanned:** ${scanned}  `,
        `**Total findings:** ${totalFindings}  `,
        `**Deterministic findings:** ${deterministicCount}  `,
        '',
        '---',
        '',
        ...buildAttackSurfaceAssessment(totalFindings, deterministicCount, scanned, filesWithFindings),
        ...buildDeterministicPanel(results),
    ];

    if (totalFindings > 0) {
        lines.push('## Findings', '');

        // Group by file
        for (const { file, findings } of results) {
            lines.push(`### \`${file}\``, '');
            const sorted = sortFindings(findings);
            for (const f of sorted) {
                lines.push(...buildFindingDetail(f, file));
            }
        }
    }

    lines.push(
        '---',
        '',
        '*Report generated by [Owlvex](https://github.com/CooperBox/CodeScanner) — deterministic security validation.*',
        '',
    );

    return lines.join('\n');
}
