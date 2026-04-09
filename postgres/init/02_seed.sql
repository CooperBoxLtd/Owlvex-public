-- ============================================================
-- Owlvex — dev seed data
-- Provides a working licence + frameworks so Phase 1/2 can be
-- tested immediately without running a billing flow.
-- ============================================================

-- ============================================================
-- Core frameworks (mirrors TDD section 4 seed block)
-- ============================================================
INSERT INTO frameworks (code, name, version, description, category, plan_tier) VALUES
  ('OWASP',     'OWASP Top 10',           'OWASP-2021',   'Critical web application security risks',                          'security',   'free'),
  ('STRIDE',    'STRIDE Threat Model',    'STRIDE-2024',  'Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation', 'security',   'developer'),
  ('MITRE',     'MITRE ATT&CK',           'MITRE-14.1',   'Adversarial tactics based on real-world observations',             'security',   'developer'),
  ('CWE',       'Common Weakness Enum',   'CWE-4.14',     'Community-developed list of software weaknesses',                  'security',   'developer'),
  ('CLEANCODE', 'Clean Code Principles',  'CC-2024',      'Robert Martin clean code and SOLID principles',                    'quality',    'developer'),
  ('NIST',      'NIST 800-53',            'NIST-R5',      'Security and privacy controls for federal information systems',    'compliance', 'team'),
  ('PCIDSS',    'PCI-DSS',               'PCI-DSS-4.0',  'Payment Card Industry Data Security Standard',                    'compliance', 'team'),
  ('HIPAA',     'HIPAA Security Rule',    'HIPAA-2024',   'Health Insurance Portability and Accountability Act controls',     'compliance', 'enterprise')
ON CONFLICT (code) DO NOTHING;

-- ============================================================
-- Dev test licence
-- Key: owlvex_lic_DEV_TEST_KEY_FOR_LOCAL_USE_ONLY
-- Hash: SHA256 of the above string
-- ============================================================
INSERT INTO licences (
    licence_key_hash,
    team_name,
    email,
    plan,
    seats,
    seats_used,
    features,
    industry_packs,
    is_active,
    expires_at
) VALUES (
    -- SHA256("owlvex_lic_DEV_TEST_KEY_FOR_LOCAL_USE_ONLY")
    '99639d09c9108e816bb20321cd7b01ad0cfeba7842350476542b0e9bed70c1bb',
    'Owlvex Dev Team',
    'dev@owlvex.local',
    'team',
    10,
    1,
    '{
        "frameworks": ["OWASP","STRIDE","MITRE","CWE","CLEANCODE","NIST","PCIDSS"],
        "scans_per_day": null,
        "prompt_editor": true,
        "comparison": true,
        "team_prompts": true,
        "ci_cd": true,
        "pdf_reports": true,
        "custom_rules": false,
        "sso": false
    }'::jsonb,
    '{"fintech"}',
    true,
    '2030-01-01T00:00:00Z'
) ON CONFLICT (licence_key_hash) DO NOTHING;

-- ============================================================
-- Baseline prompt template for OWASP scanning
-- ============================================================
INSERT INTO prompt_templates (
    framework_id,
    name,
    description,
    language,
    template,
    variables,
    is_baseline,
    plan_tier
)
SELECT
    f.id,
    'Default OWASP Security Scan',
    'Baseline security scan covering OWASP Top 10',
    'all',
    'You are a senior security engineer conducting a formal code review.

Analyse the following {language} code for security vulnerabilities using the OWASP Top 10 ({frameworks}) framework.
Severity threshold: {severity_threshold} and above only.
{team_context}

Return ONLY valid JSON matching this exact schema — no markdown, no explanation outside the JSON:
{
  "score": <float 0-10, where 10 is perfectly secure>,
  "summary": "<one sentence overall assessment>",
  "findings": [
    {
      "id": "<uuid>",
      "line": <int>,
      "line_end": <int>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "framework": "OWASP",
      "rule_code": "<e.g. OWASP-A03>",
      "title": "<short title>",
      "explanation": "<what is wrong and why it is dangerous>",
      "threat": "<what an attacker can do>",
      "fix": "<concrete remediation with code example>",
      "confidence": <float 0-1>
    }
  ],
  "positives": ["<security strength 1>", "<security strength 2>"],
  "metrics": {"critical": <int>, "high": <int>, "medium": <int>, "low": <int>}
}',
    '[
        {"name": "language", "description": "Programming language of the code", "default": "unknown"},
        {"name": "frameworks", "description": "Comma-separated framework codes", "default": "OWASP"},
        {"name": "severity_threshold", "description": "Minimum severity to report", "default": "MEDIUM"},
        {"name": "team_context", "description": "Optional team/project context", "default": ""}
    ]'::jsonb,
    true,
    'free'
FROM frameworks f
WHERE f.code = 'OWASP'
ON CONFLICT DO NOTHING;

-- ============================================================
-- OWASP Top 10 (2021) rules
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'free'
FROM frameworks f,
(VALUES
  ('OWASP-A01', 'Broken Access Control',
   'Functions, pages, or data that should be restricted to authorised users are accessible without proper authorisation checks.',
   'HIGH', ARRAY['all'], 'CWE-285',
   'Look for missing authorisation checks before privileged operations, direct object references using user-supplied IDs without ownership validation, and CORS misconfigurations.',
   'Enforce access control server-side. Use deny-by-default. Validate ownership of every object reference. Log access control failures.'),

  ('OWASP-A02', 'Cryptographic Failures',
   'Sensitive data exposed due to weak or missing encryption in transit or at rest.',
   'HIGH', ARRAY['all'], 'CWE-311',
   'Look for HTTP instead of HTTPS, weak algorithms (MD5, SHA1, DES, RC4), hard-coded keys, ECB mode, low iteration counts in key derivation.',
   'Use TLS 1.2+ for all transport. Use AES-256-GCM or ChaCha20-Poly1305 for data at rest. Use bcrypt/argon2/scrypt for passwords. Never store keys in code.'),

  ('OWASP-A03', 'Injection',
   'Untrusted data is sent to an interpreter as part of a command or query (SQL, OS, LDAP, etc.).',
   'CRITICAL', ARRAY['all'], 'CWE-89',
   'Look for string concatenation in queries, unparameterised SQL, shell execution with user input, LDAP/XPath injection, template injection, eval() with user data.',
   'Use parameterised queries / prepared statements. Never concatenate user input into commands. Use allowlists for shell arguments. Prefer ORMs with query binding.'),

  ('OWASP-A04', 'Insecure Design',
   'Flawed security design that cannot be fixed by correct implementation alone — missing threat model, no rate limiting, insecure business logic.',
   'MEDIUM', ARRAY['all'], 'CWE-284',
   'Look for missing rate limiting on sensitive endpoints, password reset flows without expiry, business logic that can be abused (negative prices, step-skipping), lack of defence-in-depth.',
   'Apply threat modelling at design time. Implement rate limiting on authentication and sensitive flows. Enforce multi-step operations server-side. Use secure design patterns.'),

  ('OWASP-A05', 'Security Misconfiguration',
   'Default credentials, unnecessary features enabled, unpatched systems, overly verbose error messages, missing security headers.',
   'MEDIUM', ARRAY['all'], 'CWE-16',
   'Look for default passwords, debug mode enabled in production, stack traces exposed to users, permissive CORS, missing CSP/HSTS/X-Frame-Options headers, verbose error messages.',
   'Harden defaults before deployment. Disable debug in production. Return generic error messages. Set all recommended security headers. Keep dependencies patched.'),

  ('OWASP-A06', 'Vulnerable and Outdated Components',
   'Using components with known vulnerabilities or without timely security patches.',
   'MEDIUM', ARRAY['all'], 'CWE-1035',
   'Look for pinned but outdated dependency versions, transitive dependencies with published CVEs, direct use of known-vulnerable library versions.',
   'Regularly audit dependencies (npm audit, pip-audit, OWASP Dependency-Check). Pin versions but monitor for CVEs. Remove unused dependencies.'),

  ('OWASP-A07', 'Identification and Authentication Failures',
   'Weaknesses in authentication that allow attackers to compromise passwords, keys, or session tokens.',
   'HIGH', ARRAY['all'], 'CWE-287',
   'Look for weak password policies, missing MFA on critical paths, session tokens in URLs, non-expiring sessions, credential stuffing vulnerabilities, insecure "remember me" implementations.',
   'Enforce strong passwords + MFA. Use secure session management (HttpOnly, Secure, SameSite cookies). Implement account lockout and brute-force protection. Invalidate sessions on logout.'),

  ('OWASP-A08', 'Software and Data Integrity Failures',
   'Code and infrastructure that does not protect against integrity violations — insecure deserialization, unsigned updates, untrusted CDNs.',
   'HIGH', ARRAY['all'], 'CWE-502',
   'Look for deserialisation of untrusted data, dynamic class loading from user input, missing signature verification on updates or plugins, use of CDN resources without SRI hashes.',
   'Never deserialise untrusted data without type constraints. Verify digital signatures on updates. Use subresource integrity (SRI) for external scripts. Prefer allow-listing deserialisable types.'),

  ('OWASP-A09', 'Security Logging and Monitoring Failures',
   'Insufficient logging means attacks go undetected and forensic analysis is impossible.',
   'LOW', ARRAY['all'], 'CWE-778',
   'Look for missing audit logs on authentication, authorisation failures, high-value transactions, absence of alerting on repeated failures, logging sensitive data (passwords, tokens) in plaintext.',
   'Log all authentication events, access control failures, and admin actions. Include timestamp, user, IP, and outcome. Never log credentials. Send logs to a centralised, tamper-resistant store.'),

  ('OWASP-A10', 'Server-Side Request Forgery',
   'Application fetches a remote resource using attacker-controlled URL without validating the destination.',
   'HIGH', ARRAY['all'], 'CWE-918',
   'Look for user-controlled URLs passed to HTTP clients, webhook URL validation, URL redirects that forward to internal resources, cloud metadata endpoint exposure (169.254.169.254).',
   'Validate and sanitise all user-supplied URLs. Use an allowlist of permitted domains/IPs. Block requests to internal RFC-1918 ranges and metadata endpoints. Prefer indirect references over raw URLs.')
) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'OWASP'
ON CONFLICT DO NOTHING;

-- ============================================================
-- STRIDE rules
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'developer'
FROM frameworks f,
(VALUES
  ('STRIDE-S', 'Spoofing Identity',
   'An attacker impersonates another user, service, or system component.',
   'HIGH', ARRAY['all'], 'CWE-287',
   'Look for missing authentication on service-to-service calls, trusting client-supplied identity headers (X-User-ID, X-Forwarded-For) without validation, weak token verification.',
   'Authenticate all service-to-service calls with mutual TLS or signed tokens. Never trust identity asserted by the client. Validate all authentication tokens server-side.'),

  ('STRIDE-T', 'Tampering with Data',
   'An attacker modifies data in transit, in storage, or in memory.',
   'HIGH', ARRAY['all'], 'CWE-345',
   'Look for missing integrity checks on messages, unsigned database records that carry security decisions, direct object modification without authorisation checks, parameter tampering.',
   'Sign or MAC all sensitive messages. Use database constraints to enforce integrity. Validate all inputs server-side. Use HTTPS/TLS for transport integrity.'),

  ('STRIDE-R', 'Repudiation',
   'An actor performs an action and can plausibly deny it due to insufficient audit logging.',
   'MEDIUM', ARRAY['all'], 'CWE-778',
   'Look for missing audit trails on financial or security-relevant operations, lack of non-repudiation mechanisms, log entries that omit actor identity or timestamp.',
   'Log every security-relevant action with actor, timestamp, and outcome. Store logs in a tamper-evident store. For high-value operations, require digital signatures.'),

  ('STRIDE-I', 'Information Disclosure',
   'Sensitive data is exposed to unauthorised parties through error messages, logs, side channels, or insecure storage.',
   'HIGH', ARRAY['all'], 'CWE-200',
   'Look for stack traces returned to clients, sensitive fields in API responses (password hashes, internal IDs), verbose error messages, PII in log files, secrets in environment variable dumps.',
   'Return generic error messages to clients. Log details server-side only. Filter sensitive fields from API responses. Classify data and enforce access accordingly.'),

  ('STRIDE-D', 'Denial of Service',
   'An attacker exhausts resources (CPU, memory, disk, network) making the service unavailable.',
   'MEDIUM', ARRAY['all'], 'CWE-400',
   'Look for missing rate limiting, unbounded resource consumption (regex catastrophic backtracking, uncontrolled loops, large payload acceptance), missing pagination on expensive queries.',
   'Implement rate limiting and request size limits. Paginate expensive queries. Use timeouts on all external calls. Apply circuit breakers for downstream dependencies.'),

  ('STRIDE-E', 'Elevation of Privilege',
   'An attacker gains capabilities beyond what they were granted.',
   'CRITICAL', ARRAY['all'], 'CWE-269',
   'Look for missing authorisation checks before privilege-changing operations, IDOR allowing access to other users'' resources, mass assignment vulnerabilities, JWT alg:none attacks, role escalation paths.',
   'Enforce least privilege throughout. Validate authorisation at every sensitive operation. Use role-based access control. Audit all privilege change paths in threat modelling.')
) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'STRIDE'
ON CONFLICT DO NOTHING;

-- ============================================================
-- CWE top weakness rules
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'developer'
FROM frameworks f,
(VALUES
  ('CWE-22', 'Path Traversal',
   'User-supplied file paths allow traversal outside the intended directory.',
   'HIGH', ARRAY['all'], 'CWE-22',
   'Look for file path construction using user input without normalisation, missing validation against a base directory, use of ../ in file names.',
   'Canonicalise file paths and verify they remain within the allowed base directory after resolution. Use Path.resolve() / os.path.realpath() then assert prefix.'),

  ('CWE-78', 'OS Command Injection',
   'User input is passed to a shell command without sanitisation.',
   'CRITICAL', ARRAY['all'], 'CWE-78',
   'Look for subprocess.call with shell=True, exec(), eval(), system() with user-controlled strings, string interpolation into shell commands.',
   'Never pass user input to shell commands. Use shell=False with argument lists. Use library functions instead of shelling out where possible.'),

  ('CWE-79', 'Cross-Site Scripting (XSS)',
   'Untrusted data is rendered in HTML without encoding, allowing script injection.',
   'HIGH', ARRAY['javascript', 'typescript', 'php', 'python', 'ruby', 'java'], 'CWE-79',
   'Look for direct HTML string concatenation with user data, innerHTML assignment, dangerouslySetInnerHTML, missing template auto-escaping, unsanitised URL parameters reflected in output.',
   'Always HTML-encode output. Use framework auto-escaping. Avoid innerHTML; use textContent. Implement a strict Content-Security-Policy.'),

  ('CWE-89', 'SQL Injection',
   'Untrusted data alters SQL query structure.',
   'CRITICAL', ARRAY['all'], 'CWE-89',
   'Look for string-formatted SQL queries, f-string or % formatting with user values, raw SQL with .format(), missing parameterisation in ORM raw() calls.',
   'Always use parameterised queries or prepared statements. Never format user input directly into SQL. Use an ORM and avoid raw SQL unless absolutely necessary.'),

  ('CWE-200', 'Sensitive Information Exposure',
   'Sensitive data inadvertently exposed through responses, logs, or error messages.',
   'MEDIUM', ARRAY['all'], 'CWE-200',
   'Look for passwords/tokens in log statements, full exception tracebacks returned to HTTP clients, PII in URLs, secrets committed to source control.',
   'Sanitise all log output. Return generic errors to clients. Use secrets managers. Implement a data classification policy.'),

  ('CWE-306', 'Missing Authentication',
   'Critical functionality is accessible without any authentication.',
   'CRITICAL', ARRAY['all'], 'CWE-306',
   'Look for admin endpoints without authentication middleware, API routes missing auth decorators, internal services accessible from public networks without credentials.',
   'Apply authentication middleware globally and opt-out explicitly for public routes. Audit every endpoint for authentication requirements. Use deny-by-default.'),

  ('CWE-311', 'Missing Encryption of Sensitive Data',
   'Sensitive data stored or transmitted without encryption.',
   'HIGH', ARRAY['all'], 'CWE-311',
   'Look for plaintext password storage, HTTP transport of sensitive data, unencrypted database columns for PII/credentials, secrets written to plaintext files.',
   'Encrypt all sensitive data at rest (AES-256) and in transit (TLS 1.2+). Use password hashing (bcrypt/argon2). Never store plaintext credentials.'),

  ('CWE-352', 'Cross-Site Request Forgery (CSRF)',
   'Authenticated users are tricked into making unintended requests.',
   'MEDIUM', ARRAY['javascript', 'typescript', 'php', 'python', 'ruby', 'java'], 'CWE-352',
   'Look for state-changing endpoints that rely solely on cookie authentication without CSRF tokens, missing SameSite cookie attribute, form submissions without CSRF validation.',
   'Use CSRF tokens for all state-changing operations. Set SameSite=Strict/Lax on session cookies. Consider double-submit cookie pattern for APIs.'),

  ('CWE-434', 'Unrestricted File Upload',
   'Uploaded files are not validated, allowing execution of malicious content.',
   'HIGH', ARRAY['all'], 'CWE-434',
   'Look for file uploads without MIME type validation, missing file extension allowlist, storing uploaded files in web-accessible directories, executing uploaded files.',
   'Validate file type by content (magic bytes), not extension alone. Store uploads outside the web root. Generate random filenames. Scan with antivirus if applicable.'),

  ('CWE-502', 'Deserialization of Untrusted Data',
   'Deserialising attacker-controlled data enables remote code execution or object injection.',
   'CRITICAL', ARRAY['python', 'java', 'php', 'ruby', 'javascript'], 'CWE-502',
   'Look for pickle.loads(), ObjectInputStream, unserialize(), YAML.load() without SafeLoader, JSON.parse() of untrusted streams passed to eval.',
   'Never deserialise untrusted data with native serialisers. Use JSON with strict type validation. If deserialisation is required, use allowlisted types only.'),

  ('CWE-611', 'XML External Entity Injection (XXE)',
   'XML parser processes external entity references, allowing file disclosure or SSRF.',
   'HIGH', ARRAY['java', 'python', 'php', 'csharp'], 'CWE-611',
   'Look for XML parsers with DTD processing enabled, missing disableExternalEntities configuration, JAXP without features set, lxml without resolve_entities=False.',
   'Disable DTD processing and external entity resolution in all XML parsers. Use a hardened parser configuration. Prefer JSON over XML for external inputs.'),

  ('CWE-798', 'Hard-coded Credentials',
   'Credentials embedded in source code are exposed to anyone with code access.',
   'CRITICAL', ARRAY['all'], 'CWE-798',
   'Look for password, api_key, secret, token literals assigned directly in code, base64-encoded credentials, AWS keys in source files, private keys committed to repositories.',
   'Remove all hard-coded credentials immediately. Use environment variables or a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault). Rotate any exposed credentials.'),

  ('CWE-862', 'Missing Authorization',
   'Authentication passes but the application does not verify the authenticated user has permission to perform the requested operation.',
   'HIGH', ARRAY['all'], 'CWE-862',
   'Look for endpoints that verify identity but not role/ownership, horizontal privilege escalation (user A accesses user B data), admin functions accessible to any authenticated user.',
   'Implement authorisation checks at every sensitive operation. Verify resource ownership, not just authentication. Use RBAC or ABAC. Test authorisation independently of authentication.'),

  ('CWE-918', 'Server-Side Request Forgery (SSRF)',
   'Server fetches a remote resource using an attacker-controlled URL, potentially accessing internal services.',
   'HIGH', ARRAY['all'], 'CWE-918',
   'Look for HTTP requests built from user input, webhook URL acceptance without validation, URL redirect that forwards downstream, file fetching by user-supplied URL.',
   'Validate all outbound URLs against an allowlist. Block RFC-1918 ranges and cloud metadata IPs. Use a dedicated egress proxy. Prefer indirect references over accepting raw URLs.')
) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'CWE'
ON CONFLICT DO NOTHING;

-- ============================================================
-- Prompt templates for STRIDE and CWE
-- ============================================================
INSERT INTO prompt_templates (framework_id, name, description, language, template, variables, is_baseline, plan_tier)
SELECT f.id,
  'Default STRIDE Threat Model Scan',
  'Threat modelling scan covering all six STRIDE categories',
  'all',
  'You are a senior security architect conducting a STRIDE threat model review.

Analyse the following {language} code for threats using the STRIDE framework ({frameworks}).
Severity threshold: {severity_threshold} and above only.
{team_context}

For each finding, identify which STRIDE category it falls under:
S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=Denial of Service, E=Elevation of Privilege

Return ONLY valid JSON matching this exact schema:
{
  "score": <float 0-10>,
  "summary": "<one sentence overall threat assessment>",
  "findings": [
    {
      "id": "<uuid>",
      "line": <int>,
      "line_end": <int>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "framework": "STRIDE",
      "rule_code": "<e.g. STRIDE-E>",
      "title": "<short title>",
      "explanation": "<what the threat is and why it is exploitable>",
      "threat": "<attacker capability and impact>",
      "fix": "<concrete mitigation>",
      "confidence": <float 0-1>
    }
  ],
  "positives": ["<security control present>"],
  "metrics": {"critical": <int>, "high": <int>, "medium": <int>, "low": <int>}
}',
  '[
    {"name": "language", "description": "Programming language", "default": "unknown"},
    {"name": "frameworks", "description": "Framework codes", "default": "STRIDE"},
    {"name": "severity_threshold", "description": "Minimum severity", "default": "MEDIUM"},
    {"name": "team_context", "description": "Optional context", "default": ""}
  ]'::jsonb,
  true,
  'developer'
FROM frameworks f WHERE f.code = 'STRIDE'
ON CONFLICT DO NOTHING;

INSERT INTO prompt_templates (framework_id, name, description, language, template, variables, is_baseline, plan_tier)
SELECT f.id,
  'Default CWE Weakness Scan',
  'Common weakness enumeration scan covering top CWE entries',
  'all',
  'You are a senior security engineer conducting a CWE-based code weakness review.

Analyse the following {language} code for software weaknesses using the CWE framework ({frameworks}).
Severity threshold: {severity_threshold} and above only.
{team_context}

Reference specific CWE IDs (e.g. CWE-89, CWE-79) for each finding.

Return ONLY valid JSON matching this exact schema:
{
  "score": <float 0-10>,
  "summary": "<one sentence overall weakness assessment>",
  "findings": [
    {
      "id": "<uuid>",
      "line": <int>,
      "line_end": <int>,
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "framework": "CWE",
      "rule_code": "<e.g. CWE-89>",
      "title": "<short title>",
      "explanation": "<what the weakness is and why it is dangerous>",
      "threat": "<what an attacker can do>",
      "fix": "<concrete remediation with code example>",
      "confidence": <float 0-1>
    }
  ],
  "positives": ["<good practice observed>"],
  "metrics": {"critical": <int>, "high": <int>, "medium": <int>, "low": <int>}
}',
  '[
    {"name": "language", "description": "Programming language", "default": "unknown"},
    {"name": "frameworks", "description": "Framework codes", "default": "CWE"},
    {"name": "severity_threshold", "description": "Minimum severity", "default": "MEDIUM"},
    {"name": "team_context", "description": "Optional context", "default": ""}
  ]'::jsonb,
  true,
  'developer'
FROM frameworks f WHERE f.code = 'CWE'
ON CONFLICT DO NOTHING;
