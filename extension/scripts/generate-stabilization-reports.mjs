import fs from 'fs';
import path from 'path';
import Module from 'module';
import { fileURLToPath } from 'url';
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const extensionRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(extensionRoot, '..');

const originalLoad = Module._load;
const vscodeMock = {
  window: {
    showInformationMessage: async () => 'Scan Selected Files',
  },
  workspace: {
    workspaceFolders: [],
    getConfiguration: () => ({
      get: (_key, defaultValue) => defaultValue,
      update: async () => undefined,
    }),
    asRelativePath: (uri) => uri.fsPath,
    openTextDocument: async (uri) => ({
      uri,
      fileName: uri.fsPath,
      languageId: detectLanguage(uri.fsPath),
      getText: () => fs.readFileSync(uri.fsPath, 'utf8'),
    }),
    fs: {
      readFile: async (uri) => fs.promises.readFile(uri.fsPath),
      writeFile: async (uri, data) => fs.promises.writeFile(uri.fsPath, Buffer.from(data)),
    },
  },
  Uri: class Uri {
    static file(fsPath) {
      return { fsPath, scheme: 'file', toString: () => fsPath };
    }
    static joinPath(base, ...segments) {
      const joined = path.join(base.fsPath, ...segments);
      return { fsPath: joined, scheme: 'file', toString: () => joined };
    }
  },
};
Module._load = function patchedLoad(request, parent, isMain) {
  if (request === 'vscode') {
    return vscodeMock;
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { ScanEngine } = await import('../out/scanner/scanEngine.js');
const { generateReportFromSnapshot } = await import('../out/scanner/reportGenerator.js');

function detectLanguage(filePath) {
  switch (path.extname(filePath).toLowerCase()) {
    case '.js':
    case '.jsx':
      return 'javascript';
    case '.ts':
    case '.tsx':
      return 'typescript';
    case '.py':
      return 'python';
    case '.java':
      return 'java';
    case '.cs':
      return 'csharp';
    case '.go':
      return 'go';
    case '.rs':
      return 'rust';
    case '.php':
      return 'php';
    case '.rb':
      return 'ruby';
    case '.cpp':
    case '.c':
    case '.h':
      return 'cpp';
    default:
      return 'plaintext';
  }
}

function configureVscodeMocks() {
  const repoUri = vscodeMock.Uri.file(repoRoot);
  vscodeMock.workspace.workspaceFolders = [{ uri: repoUri, name: 'CodeScanner', index: 0 }];
  vscodeMock.workspace.asRelativePath = (uri) => path.relative(repoRoot, uri.fsPath).replace(/\//g, '\\');
  vscodeMock.workspace.getConfiguration = () => ({
    get: (key, defaultValue) => {
      switch (key) {
        case 'apiUrl':
          return 'https://benchmark.local.test';
        case 'frameworks':
          return ['OWASP', 'STRIDE', 'CWE', 'MITRE', 'NIST', 'PCIDSS', 'CLEANCODE'];
        case 'severityThreshold':
          return 'MEDIUM';
        case 'teamContext':
          return '';
        default:
          return defaultValue;
      }
    },
    update: async () => undefined,
  });
  vscodeMock.workspace.openTextDocument = async (uri) => {
    const source = fs.readFileSync(uri.fsPath, 'utf8');
    return {
      uri,
      fileName: uri.fsPath,
      languageId: detectLanguage(uri.fsPath),
      getText: () => source,
    };
  };
  vscodeMock.workspace.fs.readFile = async (uri) => fs.promises.readFile(uri.fsPath);
  vscodeMock.workspace.fs.writeFile = async (uri, data) => {
    await fs.promises.writeFile(uri.fsPath, Buffer.from(data));
  };
}

function createJsonResponse(body, ok = true, status = 200) {
  return {
    ok,
    status,
    text: async () => JSON.stringify(body),
  };
}

let scanCounter = 0;
global.fetch = async (url) => {
  const textUrl = String(url);
  if (textUrl.endsWith('/v1/prompts/build')) {
    return createJsonResponse({
      system_prompt: 'Owlvex benchmark prompt',
      template_id: 'benchmark-prompt',
    });
  }

  if (textUrl.endsWith('/v1/scans/record')) {
    scanCounter += 1;
    return createJsonResponse({ scan_id: `benchmark-scan-${scanCounter}` });
  }

  throw new Error(`Unhandled fetch in benchmark harness: ${textUrl}`);
};

function lineOf(code, pattern) {
  const lines = code.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  return index >= 0 ? index + 1 : 1;
}

function makeFinding({ id, title, issueId, line, severity = 'HIGH', explanation, threat, fix, confidence = 0.9, likelihood = 'HIGH', likelihoodReasons = [] }) {
  return {
    id,
    line,
    line_end: line,
    severity,
    framework: 'OWASP',
    rule_code: '',
    title,
    explanation,
    threat,
    fix,
    confidence,
    issue_id: issueId,
    likelihood,
    likelihood_reasons: likelihoodReasons,
  };
}

function analyzeFile(filePath, code) {
  const file = filePath.replace(/\//g, '\\').toLowerCase();
  const findings = [];

  if (file.endsWith('\\tools\\demo\\16-open-redirect-unsafe.js') || /\bres\.redirect\(\s*req\.(query|body|params)\./i.test(code)) {
    if (!/allow-?list|ALLOWED_REDIRECTS|safeRedirect|new URL\(/i.test(code)) {
      findings.push(makeFinding({
        id: 'open-redirect',
        title: 'Open redirect through untrusted destination',
        issueId: 'owlvex.issue.open_redirect.001',
        line: lineOf(code, /redirect/i),
        severity: 'MEDIUM',
        explanation: 'A redirect destination is taken from user-controlled input without an allow-list.',
        threat: 'Attackers can steer users to attacker-controlled destinations.',
        fix: 'Allow-list redirect targets or map user input to trusted route names.',
        confidence: 0.88,
        likelihood: 'HIGH',
        likelihoodReasons: ['The redirect sink uses request-controlled input directly.'],
      }));
    }
  }

  if (file.endsWith('\\tools\\demo\\18-csrf-unsafe.js')) {
    findings.push(makeFinding({
      id: 'csrf-unsafe',
      title: 'Missing CSRF protection on state-changing request',
      issueId: 'owlvex.issue.csrf_missing_token.001',
      line: lineOf(code, /(post|put|delete|patch|update)/i),
      explanation: 'A state-changing browser request is accepted without visible CSRF protection.',
      threat: 'Attackers can trick an authenticated browser into performing unwanted actions.',
      fix: 'Require CSRF tokens or equivalent same-site browser protections.',
      confidence: 0.84,
      likelihood: 'HIGH',
      likelihoodReasons: ['The handler changes state and no CSRF validation is visible.'],
    }));
  }

  if (/UPDATE\s+users\s+SET/i.test(code)
    && /req\.body\./i.test(code)
    && /req\.session\./i.test(code)
    && !/csrfToken/i.test(code)
    && !/requireCsrf|validateCsrf/i.test(code)) {
    findings.push(makeFinding({
      id: 'csrf-update',
      title: 'Missing CSRF protection on state-changing request',
      issueId: 'owlvex.issue.csrf_missing_token.001',
      line: lineOf(code, /UPDATE\s+users\s+SET|function update/i),
      explanation: 'A state-changing browser request is accepted without visible CSRF protection.',
      threat: 'Attackers can trick an authenticated browser into performing unwanted actions.',
      fix: 'Require CSRF tokens or equivalent same-site browser protections.',
      confidence: 0.84,
      likelihood: 'HIGH',
      likelihoodReasons: ['The handler changes state and no CSRF validation is visible.'],
    }));
  }

  if (file.endsWith('\\tools\\demo\\20-cors-unsafe.js') || (/Access-Control-Allow-Origin/i.test(code) && /\*/.test(code) && /Allow-Credentials/i.test(code))) {
    findings.push(makeFinding({
      id: 'cors-unsafe',
      title: 'Overly permissive CORS policy',
      issueId: 'owlvex.issue.insecure_cors.001',
      line: lineOf(code, /Access-Control-Allow-Origin|cors/i),
      severity: 'MEDIUM',
      explanation: 'The CORS policy allows broad cross-origin access that is wider than necessary.',
      threat: 'Unexpected origins may be able to interact with sensitive endpoints.',
      fix: 'Restrict CORS origins and credential use to explicit trusted callers.',
      confidence: 0.86,
      likelihood: 'MEDIUM',
      likelihoodReasons: ['Wildcard CORS behavior is visible in the file.'],
    }));
  }

  if (file.endsWith('\\tools\\demo\\22-ssrf-unsafe.js')
    || file.endsWith('\\tools\\demo\\30-ssrf-allowlist-unsafe.js')
    || /\bfetch\s*\(\s*req\.(query|body|params)\./i.test(code)
    || (/new URL\s*\(\s*req\.(query|body|params)\./i.test(code) && /\bfetch\s*\(\s*url\.toString\(\)\s*\)/i.test(code))) {
    if (!/isAllowedOutboundUrl|allow-?list|allowedHosts|TRUSTED_HOSTS|ALLOWED_HOSTS|SAFE_HOSTS/i.test(code)
      || /\.includes\s*\(\s*['"][^'"]+['"]\s*\)/i.test(code)) {
      findings.push(makeFinding({
        id: 'ssrf-unsafe',
        title: 'Server-side request forgery through untrusted destination',
        issueId: 'owlvex.issue.ssrf.001',
        line: lineOf(code, /\bfetch\s*\(/i),
        explanation: 'A server-side outbound request uses a user-controlled destination without a trusted allow-list.',
        threat: 'Attackers can pivot requests into internal services or metadata endpoints.',
        fix: 'Normalize URLs and restrict outbound destinations with a trusted allow-list.',
        confidence: 0.83,
        likelihood: 'HIGH',
        likelihoodReasons: ['Untrusted input flows directly into an outbound fetch call.'],
      }));
    }
  }

  if (file.endsWith('\\tools\\demo\\28-path-traversal-unsafe.js')
    || (/path\.(join|resolve)\s*\(\s*['"][^'"]+['"]\s*,\s*req\.(query|body|params)\./i.test(code)
      && /\b(sendFile|readFile|createReadStream)\s*\(/i.test(code))) {
    if (!/SAFE_FILES|ALLOWED_FILES|safeFiles|allowedFiles|Map\(/i.test(code)) {
      findings.push(makeFinding({
        id: 'path-traversal-unsafe',
        title: 'Path traversal through user-controlled filesystem path',
        issueId: 'owlvex.issue.path_traversal.001',
        line: lineOf(code, /path\.(join|resolve)|sendFile|readFile/i),
        explanation: 'User-controlled path input reaches a filesystem boundary without a safe identifier map or boundary check.',
        threat: 'Attackers can read or access unintended files outside the intended directory.',
        fix: 'Map user choices to trusted identifiers and keep resolved paths inside a fixed directory boundary.',
        confidence: 0.87,
        likelihood: 'HIGH',
        likelihoodReasons: ['Untrusted input is joined directly into a filesystem path before file access.'],
      }));
    }
  }

  if (file.endsWith('\\tools\\demo\\24-jwt-validation-unsafe.js') || /decodeJwtWithoutVerification|Buffer\.from\(.*split\('\.'\)\[1\]/i.test(code)) {
    findings.push(makeFinding({
      id: 'jwt-unsafe',
      title: 'Weak JWT validation',
      issueId: 'owlvex.issue.weak_jwt_validation.001',
      line: lineOf(code, /decodeJwtWithoutVerification|Buffer\.from/i),
      explanation: 'JWT claims are decoded without full signature validation before they are trusted.',
      threat: 'Attackers can tamper with token claims and bypass authentication or authorization decisions.',
      fix: 'Verify signature, issuer, audience, expiry, and accepted algorithms before trusting claims.',
      confidence: 0.82,
      likelihood: 'HIGH',
      likelihoodReasons: ['The token payload is decoded without full verification.'],
    }));
  }

  if (/\bjwt\.decode\s*\(/i.test(code)) {
    findings.push(makeFinding({
      id: 'jwt-decode-without-verify',
      title: 'Weak JWT validation',
      issueId: 'owlvex.issue.weak_jwt_validation.001',
      line: lineOf(code, /\bjwt\.decode\s*\(/i),
      explanation: 'JWT claims are decoded without full signature validation before they are trusted.',
      threat: 'Attackers can tamper with token claims and bypass authentication or authorization decisions.',
      fix: 'Verify signature, issuer, audience, expiry, and accepted algorithms before trusting claims.',
      confidence: 0.82,
      likelihood: 'HIGH',
      likelihoodReasons: ['The code calls jwt.decode directly without verification.'],
    }));
  }

  if (/SELECT\s+id,\s*email\s+FROM\s+users\s+WHERE\s+email\s*=\s*'\$\{email\}'/i.test(code)) {
    findings.push(makeFinding({
      id: 'db-sqli',
      title: 'Unsanitized SQL query construction',
      issueId: 'owlvex.issue.sql_injection.001',
      line: lineOf(code, /SELECT\s+id,\s*email\s+FROM\s+users/i),
      severity: 'CRITICAL',
      explanation: 'An SQL query is built by interpolating untrusted input directly into the query string.',
      threat: 'Attackers can inject SQL and access or manipulate data outside the intended query scope.',
      fix: 'Use parameterized queries and keep user input out of the SQL string itself.',
      confidence: 0.89,
      likelihood: 'HIGH',
      likelihoodReasons: ['The SQL string directly interpolates user-controlled input.'],
    }));
  }

  if (/const\s+DEMO_SECRET\s*=\s*['"][^'"]+['"]/i.test(code)) {
    findings.push(makeFinding({
      id: 'hardcoded-token',
      title: 'Hardcoded token in source code',
      issueId: 'owlvex.issue.hardcoded_token.001',
      line: lineOf(code, /const\s+DEMO_SECRET\s*=/i),
      severity: 'CRITICAL',
      explanation: 'A reusable secret or token is embedded directly in source code.',
      threat: 'Attackers who obtain the code can reuse the secret to forge or access protected data.',
      fix: 'Move the secret to managed configuration and rotate the exposed value.',
      confidence: 1,
      likelihood: 'HIGH',
      likelihoodReasons: ['The secret value is committed directly in source.'],
    }));
  }

  if (file.endsWith('\\tools\\demo\\26-deserialization-unsafe.py') || /pickle\.loads\(/i.test(code)) {
    findings.push(makeFinding({
      id: 'deser-unsafe',
      title: 'Insecure deserialization of untrusted data',
      issueId: 'owlvex.issue.insecure_deserialization.001',
      line: lineOf(code, /pickle\.loads|yaml\.load|deserialize|unserialize/i),
      explanation: 'Executable or object deserialization is performed on untrusted input.',
      threat: 'Attackers can trigger code execution or unsafe object materialization.',
      fix: 'Replace unsafe deserializers with safe data-only formats and validate payloads before use.',
      confidence: 0.81,
      likelihood: 'HIGH',
      likelihoodReasons: ['The source contains an executable deserialization primitive.'],
    }));
  }

  if (file.endsWith('\\tools\\demo-app\\src\\db.js') || /function getDocumentById\s*\(/i.test(code)) {
    findings.push(makeFinding({
      id: 'db-idor',
      title: 'Broken Access Control in getDocumentById',
      line: lineOf(code, /function getDocumentById/i),
      explanation: 'The helper returns a document by ID without verifying ownership or tenant scope.',
      threat: 'Attackers could access another user or tenant document.',
      fix: 'Add an ownership or tenant constraint before returning the document.',
      confidence: 0.8,
      likelihood: 'HIGH',
      likelihoodReasons: ['The helper accepts a direct resource identifier without access checks.'],
    }));
  }

  return findings;
}

function buildReviewResponse(prompt) {
  const candidatesMatch = prompt.match(/Candidates:\n([\s\S]*?)\n\nCode:\n([\s\S]*)$/);
  if (!candidatesMatch) {
    return { reviews: [] };
  }

  const candidates = JSON.parse(candidatesMatch[1]);
  const code = candidatesMatch[2];
  const syntheticPath = `in-memory-${Math.random()}`;
  const supported = analyzeFile(syntheticPath, code);
  const role = prompt.includes('You are the Skeptic pass.') ? 'skeptic' : 'verifier';

  const reviews = candidates.map((candidate) => {
    const match = supported.find((finding) =>
      (candidate.canonical_id && candidate.canonical_id === finding.issue_id)
      || candidate.title === finding.title
      || candidate.line === finding.line
    );

    if (role === 'verifier') {
      return {
        id: candidate.id,
        verdict: match ? 'support' : 'reject',
        reason: match ? 'Local code evidence supports this claim.' : 'Local code evidence does not support this claim.',
      };
    }

    return {
      id: candidate.id,
      verdict: match ? 'clear' : 'contradict',
      reason: match ? 'No stronger contradictory local evidence is visible.' : 'The claimed issue is contradicted by the local code context.',
    };
  });

  return { reviews };
}

function createBenchmarkProvider() {
  return {
    id: 'benchmark-local',
    selectedModel: 'benchmark-single-agent',
    async complete(req) {
      if (req.userMessage.includes('Analyse this ')) {
        const codeMatch = req.userMessage.match(/\nCode:\n\n([\s\S]*)$/);
        const code = codeMatch ? codeMatch[1] : '';
        const pathHintMatch = req.userMessage.match(/Analyse this\s+([a-z]+)\s+code\./i);
        const findings = analyzeFile(pathHintMatch?.[1] ?? 'unknown', code);
        return {
          content: JSON.stringify({
            score: findings.length ? Math.max(0, 10 - findings.length * 2) : 10,
            summary: findings.length ? `${findings.length} AI candidate finding(s) detected.` : 'No findings detected.',
            findings,
            positives: [],
            metrics: { critical: 0, high: findings.filter(f => f.severity === 'HIGH').length, medium: findings.filter(f => f.severity === 'MEDIUM').length, low: findings.filter(f => f.severity === 'LOW').length },
          }),
          tokenCount: 100,
        };
      }

      return {
        content: JSON.stringify(buildReviewResponse(req.userMessage)),
        tokenCount: 40,
      };
    },
  };
}

function buildLicenceManager() {
  return {
    async getKey() {
      return 'benchmark-licence';
    },
    async validate() {
      return { valid: true, features: { frameworks: ['OWASP'] } };
    },
  };
}

function buildRegistry(provider) {
  return {
    getActive() {
      return provider;
    },
  };
}

async function scanFiles(targetLabel, outputRoot, files) {
  const provider = createBenchmarkProvider();
  const engine = new ScanEngine(buildLicenceManager(), buildRegistry(provider));
  const results = [];

  for (const filePath of files) {
    const uri = vscodeMock.Uri.file(filePath);
    const document = await vscodeMock.workspace.openTextDocument(uri);
    const result = await engine.scanDocument(document);
    results.push({ uri, result });
  }

  return generateReportFromSnapshot(outputRoot, {
    targetLabel,
    outputRoot,
    errors: [],
    results,
  });
}

function listDemoFiles() {
  const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, 'tools', 'demo', 'benchmark.expectations.json'), 'utf8'));
  return manifest.expectations.map((entry) => path.join(repoRoot, 'tools', 'demo', entry.file));
}

function listDemoAppFiles() {
  const srcRoot = path.join(repoRoot, 'tools', 'demo-app', 'src');
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (/\.(js|ts|jsx|tsx|py)$/i.test(entry.name)) {
        out.push(full);
      }
    }
  };
  walk(srcRoot);
  return out.sort();
}

async function main() {
  configureVscodeMocks();
  const demoRoot = vscodeMock.Uri.file(path.join(repoRoot, 'tools', 'demo'));
  const demoAppRoot = vscodeMock.Uri.file(path.join(repoRoot, 'tools', 'demo-app'));

  const demoReport = await scanFiles('tools/demo', demoRoot, listDemoFiles());
  const demoAppReport = await scanFiles('tools/demo-app', demoAppRoot, listDemoAppFiles());

  console.log(`Demo report: ${demoReport.fsPath}`);
  console.log(`Demo-app report: ${demoAppReport.fsPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
