import fs from 'node:fs/promises';
import path from 'node:path';
import { repoRoot, toolRoot } from './repo-root.mjs';

const manifestPath = path.join(toolRoot, 'ai-evals', 'manifest.json');
const runsDir = path.join(toolRoot, 'runs', 'ai-evals');

function usage() {
  return 'Usage: npm run benchmark:ai-evals -- <report.md> [model-tag]';
}

function normalizeText(value) {
  return String(value ?? '').trim().toLowerCase();
}

function humanizeIssueId(issueId) {
  const match = String(issueId ?? '').match(/owlvex\.issue\.([a-z0-9_]+)\.\d+$/i);
  if (!match?.[1]) {
    return normalizeText(issueId);
  }

  return match[1].replace(/_/g, ' ');
}

function issueIdNeedles(issueId) {
  const humanized = humanizeIssueId(issueId);
  const tokens = humanized
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean)
    .filter((token) => !['missing', 'token', 'through', 'untrusted', 'destination', 'state', 'changing', 'request', 'protection', 'policy'].includes(token));

  return [...new Set([normalizeText(issueId), humanized, ...tokens.map(normalizeText)])];
}

function toTimestamp(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function parseFrameworks(markdown) {
  const match = markdown.match(/^- Frameworks in scope:\s+(.+)$/m);
  if (!match?.[1]) {
    return [];
  }

  return match[1]
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseReport(markdown) {
  const lines = markdown.split(/\r?\n/);
  const findingsByFile = new Map();
  const frameworksInScope = parseFrameworks(markdown);
  let currentFile = null;
  let currentFinding = null;
  let inDetectionTable = false;
  let expectingDetectionDivider = false;

  function ensureFile(file) {
    if (!findingsByFile.has(file)) {
      findingsByFile.set(file, []);
    }
    return findingsByFile.get(file);
  }

  function pushCurrentFinding() {
    if (!currentFile || !currentFinding) {
      currentFinding = null;
      return;
    }

    if (Array.isArray(currentFinding.detailLines)) {
      currentFinding.detailText = currentFinding.detailLines.join('\n').trim();
      delete currentFinding.detailLines;
    }

    const bucket = ensureFile(currentFile);
    if (!bucket.includes(currentFinding)) {
      bucket.push(currentFinding);
    }
    currentFinding = null;
  }

  for (const line of lines) {
    const fileMatch = line.match(/^###\s+(.+)$/);
    if (fileMatch) {
      pushCurrentFinding();
      currentFile = fileMatch[1].trim();
      inDetectionTable = false;
      expectingDetectionDivider = false;
      continue;
    }

    if (!currentFile) {
      continue;
    }

    if (line === '| Finding | Score Factors | Detection |') {
      inDetectionTable = true;
      expectingDetectionDivider = true;
      continue;
    }

    if (inDetectionTable && expectingDetectionDivider) {
      expectingDetectionDivider = false;
      continue;
    }

    if (inDetectionTable && line.startsWith('| ') && line.endsWith(' |')) {
      const raw = line.trim().slice(1, -1);
      const firstSep = raw.indexOf(' | ');
      const lastSep = raw.lastIndexOf(' | ');
      const title = firstSep >= 0 ? raw.slice(0, firstSep).trim() : '';
      const detection = lastSep >= 0 ? raw.slice(lastSep + 3).trim() : '';
      if (!title) {
        continue;
      }

      const entry = {
        title,
        canonicalTitle: title,
        provenance: detection?.startsWith('AI ') ? 'ai' : detection?.startsWith('Deterministic ') ? 'deterministic' : 'unknown',
        confidence: detection?.startsWith('AI ')
          ? Number.parseInt(detection.replace(/^AI\s+/, '').replace('%', ''), 10) || null
          : null,
        canonicalId: '',
        severity: '',
        likelihood: '',
        riskScore: null,
        detailLines: [],
      };
      ensureFile(currentFile).push(entry);
      continue;
    }

    if (inDetectionTable && !line.startsWith('|')) {
      inDetectionTable = false;
    }

    const detailMatch = line.match(/^####\s+(.+)$/);
    if (detailMatch) {
      pushCurrentFinding();
      const title = detailMatch[1].trim();
      const existing = ensureFile(currentFile).find((item) => item.title === title);
      currentFinding = existing ?? {
        title,
        canonicalTitle: title,
        provenance: 'unknown',
        confidence: null,
        canonicalId: '',
        severity: '',
        likelihood: '',
        riskScore: null,
        detailLines: [],
      };
      if (!existing) {
        const list = ensureFile(currentFile);
        list.splice(list.length, 0, currentFinding);
      }
      continue;
    }

    if (!currentFinding) {
      continue;
    }

    const riskMatch = line.match(/^- Risk:\s+([A-Z]+) impact \/ ([A-Z]+) likelihood \/ (\d+)\/10$/);
    if (riskMatch) {
      currentFinding.severity = riskMatch[1];
      currentFinding.likelihood = riskMatch[2];
      currentFinding.riskScore = Number.parseInt(riskMatch[3], 10);
      continue;
    }

    const mappingsMatch = line.match(/^- Mappings:\s+(.+)$/);
    if (mappingsMatch) {
      const cweMatch = mappingsMatch[1].match(/CWE:\s+([^|]+)/);
      if (cweMatch?.[1]) {
        currentFinding.cwe = cweMatch[1].trim();
      }
    }

    if (Array.isArray(currentFinding.detailLines)) {
      currentFinding.detailLines.push(line);
    }
  }

  pushCurrentFinding();
  return {
    frameworksInScope,
    findingsByFile,
  };
}

function verdictFromFindings(findings) {
  if (!findings.length) {
    return 'clean';
  }

  if (findings.every((finding) => normalizeText(finding.severity) === 'low')) {
    return 'advisory';
  }

  return 'vulnerable';
}

function scoreVerdict(expected, actual) {
  const verdict = normalizeText(actual);
  if (expected === 'ai-finding') {
    return verdict === 'vulnerable' || verdict === 'advisory';
  }

  if (expected === 'clean-or-advisory') {
    return ['clean', 'advisory', 'informational', 'none'].includes(verdict);
  }

  return normalizeText(expected) === verdict;
}

function includesIssueId(findings, expectedIds) {
  const haystack = findings.flatMap((finding) => [
    finding.canonicalId ?? '',
    finding.title ?? '',
    finding.canonicalTitle ?? '',
  ]).map(normalizeText);

  return expectedIds.some((id) => {
    const needles = issueIdNeedles(id);
    return needles.some((needle) => haystack.some((value) => value.includes(needle)));
  });
}

function excludesIssueId(findings, forbiddenIds) {
  const haystack = findings.flatMap((finding) => [
    finding.canonicalId ?? '',
    finding.title ?? '',
    finding.canonicalTitle ?? '',
  ]).map(normalizeText);

  return forbiddenIds.every((id) => {
    const needles = issueIdNeedles(id);
    return needles.every((needle) => haystack.every((value) => !value.includes(needle)));
  });
}

function includesLabel(findings, labels) {
  const haystack = findings.flatMap((finding) => [
    finding.title ?? '',
    finding.canonicalTitle ?? '',
  ]).map(normalizeText);

  return labels.some((label) => haystack.some((value) => value.includes(normalizeText(label))));
}

function excludesLabel(findings, labels) {
  const haystack = findings.flatMap((finding) => [
    finding.title ?? '',
    finding.canonicalTitle ?? '',
  ]).map(normalizeText);

  return labels.every((label) => haystack.every((value) => !value.includes(normalizeText(label))));
}

function matchesProvenance(findings, expectedProvenance) {
  return findings.some((finding) => normalizeText(finding.provenance) === normalizeText(expectedProvenance));
}

function matchesFrameworkScope(actualFrameworks, expectedFrameworks) {
  const actual = new Set((actualFrameworks ?? []).map(normalizeText));
  return expectedFrameworks.every((framework) => actual.has(normalizeText(framework)));
}

function includesText(findings, snippets) {
  const haystack = findings
    .map((finding) => normalizeText(finding.detailText))
    .join('\n');

  return snippets.some((snippet) => haystack.includes(normalizeText(snippet)));
}

function excludesText(findings, snippets) {
  const haystack = findings
    .map((finding) => normalizeText(finding.detailText))
    .join('\n');

  return snippets.every((snippet) => !haystack.includes(normalizeText(snippet)));
}

function scoreCase(caseDefinition, findings, frameworksInScope) {
  const expected = caseDefinition.expected;
  const checks = [
    {
      name: 'verdict',
      passed: scoreVerdict(expected.verdict, verdictFromFindings(findings)),
    },
  ];

  if (expected.preferred_issue_ids) {
    checks.push({
      name: 'preferred_issue_ids',
      passed: includesIssueId(findings, expected.preferred_issue_ids),
    });
  }

  if (expected.must_not_include_issue_ids) {
    checks.push({
      name: 'must_not_include_issue_ids',
      passed: excludesIssueId(findings, expected.must_not_include_issue_ids),
    });
  }

  if (expected.preferred_labels) {
    checks.push({
      name: 'preferred_labels',
      passed: includesLabel(findings, expected.preferred_labels),
    });
  }

  if (expected.must_not_include_labels) {
    checks.push({
      name: 'must_not_include_labels',
      passed: excludesLabel(findings, expected.must_not_include_labels),
    });
  }

  if (expected.preferred_provenance) {
    checks.push({
      name: 'preferred_provenance',
      passed: matchesProvenance(findings, expected.preferred_provenance),
    });
  }

  if (expected.frameworks_in_scope) {
    checks.push({
      name: 'frameworks_in_scope',
      passed: matchesFrameworkScope(frameworksInScope, expected.frameworks_in_scope),
    });
  }

  if (expected.must_include_text) {
    checks.push({
      name: 'must_include_text',
      passed: includesText(findings, expected.must_include_text),
    });
  }

  if (expected.must_not_include_text) {
    checks.push({
      name: 'must_not_include_text',
      passed: excludesText(findings, expected.must_not_include_text),
    });
  }

  return {
    id: caseDefinition.id,
    file: caseDefinition.file,
    verdict: verdictFromFindings(findings),
    frameworksInScope,
    findings,
    passed: checks.every((check) => check.passed),
    passedChecks: checks.filter((check) => check.passed).length,
    totalChecks: checks.length,
    checks,
  };
}

async function writeArtifacts(summary, detailedResults) {
  await fs.mkdir(runsDir, { recursive: true });
  const timestamp = toTimestamp(new Date(summary.generatedAt));

  const latestPath = path.join(runsDir, 'latest.json');
  const latestResultsPath = path.join(runsDir, 'latest.results.json');
  const historicalPath = path.join(runsDir, `${timestamp}.json`);
  const historicalResultsPath = path.join(runsDir, `${timestamp}.results.json`);

  await fs.writeFile(latestPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  await fs.writeFile(latestResultsPath, `${JSON.stringify(detailedResults, null, 2)}\n`, 'utf8');
  await fs.writeFile(historicalPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  await fs.writeFile(historicalResultsPath, `${JSON.stringify(detailedResults, null, 2)}\n`, 'utf8');
}

async function main() {
  const reportArg = process.argv[2];
  const modelArg = process.argv[3] ?? 'unspecified-model';

  if (!reportArg || reportArg === '--help' || reportArg === '-h') {
    console.log(usage());
    return;
  }

  const reportPath = path.resolve(repoRoot, reportArg);
  const [manifestRaw, reportRaw] = await Promise.all([
    fs.readFile(manifestPath, 'utf8'),
    fs.readFile(reportPath, 'utf8'),
  ]);

  const manifest = JSON.parse(manifestRaw);
  const parsedReport = parseReport(reportRaw);
  const generatedAt = new Date().toISOString();

  const results = manifest.cases.map((caseDefinition) => {
    const basename = path.basename(caseDefinition.file);
    const findings = parsedReport.findingsByFile.get(basename) ?? [];
    return scoreCase(caseDefinition, findings, parsedReport.frameworksInScope);
  });

  const summary = {
    suite: manifest.suite,
    generatedAt,
    report: path.relative(repoRoot, reportPath).replaceAll('\\', '/'),
    run: {
      model: modelArg,
      frameworks: parsedReport.frameworksInScope,
    },
    passed: results.every((result) => result.passed),
    totalCases: results.length,
    passedCases: results.filter((result) => result.passed).length,
    failedCases: results.filter((result) => !result.passed).map((result) => result.id),
  };

  const detailedResults = {
    ...summary,
    cases: results,
  };

  await writeArtifacts(summary, detailedResults);
  console.log(JSON.stringify(detailedResults, null, 2));

  if (!summary.passed) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
