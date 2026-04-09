-- ============================================================
-- Owlvex — extended rule data
-- Adds: MITRE ATT&CK, Clean Code, NIST 800-53, PCI-DSS rules
-- Adds: language-specific rule variants for CWE-89, CWE-79, CWE-78
-- Run after 02_seed.sql
-- ============================================================


-- ============================================================
-- MITRE ATT&CK for software (focused on code-detectable tactics)
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'developer'
FROM frameworks f,
(VALUES
  ('MITRE-T1190', 'Exploit Public-Facing Application',
   'Attackers exploit weaknesses in internet-facing applications to gain initial access.',
   'CRITICAL', ARRAY['all'], 'CWE-284',
   'Look for unvalidated user input flowing into SQL queries, shell commands, XML parsers, or template engines. Check for missing input length limits on public endpoints. Look for debug endpoints or admin routes exposed without authentication.',
   'Apply input validation at all public boundaries. Disable debug endpoints in production. Enforce authentication on all non-public routes. Use a WAF for additional defence-in-depth.'),

  ('MITRE-T1059', 'Command and Scripting Interpreter Abuse',
   'Attackers use scripting interpreters to execute malicious commands.',
   'CRITICAL', ARRAY['all'], 'CWE-78',
   'Look for eval(), exec(), subprocess with shell=True, Runtime.exec(), system(), popen() with string interpolation. Check for dynamic code generation from user input. Look for template engines rendering untrusted content.',
   'Never pass user-controlled data to interpreters. Use shell=False with argument lists. Replace eval() with safe alternatives. Validate and sanitise all inputs before any dynamic execution.'),

  ('MITRE-T1552', 'Unsecured Credentials',
   'Attackers find credentials stored insecurely in code, config files, or environment variables.',
   'HIGH', ARRAY['all'], 'CWE-798',
   'Look for password, secret, key, token, api_key assigned as string literals. Check for base64-encoded strings that decode to credentials. Look for .env files committed to source, AWS access keys in code (AKIA prefix), private key PEM blocks in source files.',
   'Use a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault). Load credentials from environment variables injected at runtime. Rotate any credentials found in code immediately. Add pre-commit hooks to detect secrets.'),

  ('MITRE-T1110', 'Brute Force',
   'Attackers attempt multiple credentials to gain unauthorised access.',
   'MEDIUM', ARRAY['all'], 'CWE-307',
   'Look for login, authentication, or password-reset endpoints with no rate limiting. Check for missing account lockout after failed attempts. Look for predictable session tokens or sequential IDs used as authentication. Check for missing CAPTCHA on public auth forms.',
   'Implement rate limiting (e.g. token bucket) on all authentication endpoints. Lock accounts after N failed attempts. Use exponential backoff. Add CAPTCHA for repeated failures. Enforce strong password policies.'),

  ('MITRE-T1548', 'Abuse Elevation Control Mechanism',
   'Attackers exploit privilege escalation mechanisms in code to gain higher permissions.',
   'HIGH', ARRAY['all'], 'CWE-269',
   'Look for role or permission checks that use client-supplied values without server-side validation. Check for JWT claims accepted without signature verification. Look for sudo/setuid patterns, missing ownership checks on privileged operations, mass assignment vulnerabilities that allow role inflation.',
   'Validate all privilege checks server-side. Never trust client-supplied role or permission values. Verify JWT signatures and validate all claims. Use allowlists for permitted operations per role.'),

  ('MITRE-T1565', 'Data Manipulation',
   'Attackers alter data to achieve objectives — integrity attacks on stored or transmitted data.',
   'HIGH', ARRAY['all'], 'CWE-345',
   'Look for missing integrity checks on critical data (orders, balances, permissions). Check for unsigned or unverified data flowing into decision-making logic. Look for race conditions on state-changing operations (TOCTOU). Check for missing audit trails on data modification.',
   'Add integrity checks (HMAC, digital signatures) to critical data. Use database transactions with proper isolation. Log all data modifications with actor, timestamp, and before/after values. Implement optimistic locking for concurrent writes.'),

  ('MITRE-T1078', 'Valid Accounts',
   'Attackers use valid credentials obtained through phishing, credential stuffing, or prior breach.',
   'MEDIUM', ARRAY['all'], 'CWE-287',
   'Look for lack of MFA enforcement on privileged operations. Check for long-lived sessions without re-authentication for sensitive actions. Look for single-factor authentication on admin panels. Check for missing notification to user on suspicious login (new device, new location).',
   'Enforce MFA on all privileged and sensitive operations. Implement anomaly detection for login patterns. Use short-lived tokens with refresh flows. Require re-authentication before high-risk operations (password change, payment, export).'),

  ('MITRE-T1040', 'Network Sniffing — Cleartext Protocols',
   'Sensitive data transmitted in cleartext can be intercepted on the network.',
   'HIGH', ARRAY['all'], 'CWE-319',
   'Look for HTTP URLs in API calls, FTP/Telnet usage, unencrypted WebSocket connections (ws:// vs wss://), plaintext SMTP without STARTTLS, database connections without SSL/TLS flags set.',
   'Enforce HTTPS/TLS on all network communication. Set HSTS headers. Use TLS 1.2 minimum. Verify certificates (do not skip SSL verification in production code). Enable SSL/TLS on all database connections.')

) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'MITRE'
ON CONFLICT DO NOTHING;


-- ============================================================
-- Clean Code / SOLID principles (quality framework)
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'developer'
FROM frameworks f,
(VALUES
  ('CC-G001', 'Dead Code',
   'Unreachable, commented-out, or unused code that increases maintenance burden and hides intent.',
   'LOW', ARRAY['all'], NULL,
   'Look for commented-out code blocks, unreachable branches after return/throw, unused variables, unused function parameters, unused imports. Check for TODO/FIXME/HACK comments that indicate unfinished work left in production code.',
   'Remove dead code rather than commenting it out — version control preserves history. Resolve or track TODOs in your issue tracker. Run a linter with unused-variable and unreachable-code rules.'),

  ('CC-G002', 'Function Too Long',
   'Functions exceeding ~30 lines are harder to test, understand, and maintain.',
   'MEDIUM', ARRAY['all'], NULL,
   'Look for functions longer than 30-40 lines. Check for deeply nested loops or conditionals (more than 3 levels deep). Look for functions that do more than one thing (mixing data access, business logic, and presentation). Check for long parameter lists (more than 4-5 parameters).',
   'Apply Single Responsibility Principle — one function, one reason to change. Extract sub-tasks into well-named helper functions. Use early returns to flatten nesting. Replace long parameter lists with parameter objects or builder patterns.'),

  ('CC-G003', 'Magic Numbers and Strings',
   'Unexplained numeric or string literals make code intent unclear and changes error-prone.',
   'LOW', ARRAY['all'], NULL,
   'Look for unexplained numeric literals (other than 0, 1, -1) in business logic. Check for hardcoded string literals used in comparisons or conditions. Look for repeated identical literals across the codebase.',
   'Extract magic values to named constants or enums. Group related constants in a dedicated module. Use configuration files for values that might change per environment.'),

  ('CC-G004', 'Deep Nesting',
   'Code nested more than 3-4 levels deep is difficult to read and reason about.',
   'MEDIUM', ARRAY['all'], NULL,
   'Look for if/for/while nesting beyond 3 levels. Check for arrow anti-pattern in callbacks (deeply nested anonymous functions). Look for complex switch/case structures with nested logic inside each case.',
   'Use early returns (guard clauses) to invert conditions and reduce nesting. Extract nested blocks into named functions. Use functional patterns (map, filter, reduce) to flatten loops. Apply the Decompose Conditional refactoring.'),

  ('CC-G005', 'Large Class / God Object',
   'Classes with too many responsibilities violate SRP and become maintenance liabilities.',
   'MEDIUM', ARRAY['all'], NULL,
   'Look for classes with more than 10-15 public methods. Check for classes that contain both data access and business logic. Look for classes with names ending in Manager, Handler, Processor, Utils that accumulate unrelated responsibilities.',
   'Apply Single Responsibility Principle. Split large classes by responsibility. Use composition over inheritance. Extract cohesive subsets of methods into dedicated classes.'),

  ('CC-G006', 'Duplicate Code',
   'Copy-pasted logic creates maintenance traps — bugs must be fixed in multiple places.',
   'MEDIUM', ARRAY['all'], NULL,
   'Look for identical or near-identical code blocks appearing multiple times. Check for repeated conditional logic that could be abstracted. Look for copy-pasted error handling. Check for near-duplicate class hierarchies.',
   'Extract duplicated logic into a shared function or class. Apply DRY principle but only when the duplication represents the same concept — do not over-abstract. Use inheritance or composition for common behaviour.'),

  ('CC-G007', 'Poor Error Handling',
   'Swallowing exceptions, logging and continuing, or exposing internals in error messages.',
   'HIGH', ARRAY['all'], NULL,
   'Look for empty catch blocks, catch blocks that only call console.log/print then continue, bare except clauses in Python, catching Exception/Throwable at high levels without re-raising. Check for stack traces returned to end users. Look for error messages that reveal internal paths, database schemas, or implementation details.',
   'Handle each exception at the appropriate level. Either recover from the exception or re-raise it. Never swallow exceptions silently. Return generic error messages to users; log details server-side. Use typed exceptions/error codes for programmatic handling.'),

  ('CC-S001', 'Missing Dependency Injection',
   'Hard-coded dependencies make code untestable and tightly coupled.',
   'LOW', ARRAY['all'], NULL,
   'Look for direct instantiation of collaborators inside constructors or methods (new DatabaseConnection(), new HttpClient() inside business logic). Check for static method calls to concrete implementations. Look for singleton patterns that cannot be replaced in tests.',
   'Pass dependencies via constructor injection. Define interfaces/protocols for external collaborators. Use a DI container for complex dependency graphs. Never instantiate infrastructure dependencies inside domain logic.')

) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'CLEANCODE'
ON CONFLICT DO NOTHING;


-- ============================================================
-- NIST 800-53 (key controls translatable to code review)
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'team'
FROM frameworks f,
(VALUES
  ('NIST-AC-3', 'Access Enforcement',
   'The system enforces approved authorisations for logical access to information and system resources.',
   'HIGH', ARRAY['all'], 'CWE-284',
   'Look for missing role or permission checks before accessing resources. Check for access control logic that trusts client-supplied user IDs or roles. Look for admin functions accessible to non-admin users. Check for missing ownership validation on object access (IDOR).',
   'Implement centralised access control. Validate permissions server-side on every request. Use deny-by-default. Log access control failures and alert on anomalies.'),

  ('NIST-AC-6', 'Least Privilege',
   'Processes and users operate with only the minimum permissions necessary.',
   'MEDIUM', ARRAY['all'], 'CWE-269',
   'Look for database connections with admin/root privileges used for routine queries. Check for service accounts with write access when only read is needed. Look for wildcard permissions (*) in IAM policies or SQL grants. Check for tokens or API keys with broader scope than required.',
   'Apply least privilege at every layer. Use read-only database users for read operations. Scope tokens and API keys to minimum required permissions. Review and tighten IAM policies regularly.'),

  ('NIST-AU-2', 'Audit Events',
   'The system identifies the types of events that require auditing.',
   'MEDIUM', ARRAY['all'], 'CWE-778',
   'Look for authentication events (success and failure) not being logged. Check for missing audit logs on privileged operations (admin actions, permission changes, data exports). Look for business-critical transactions (payments, account changes) without audit trails. Check for logs that omit actor identity or timestamp.',
   'Log all authentication events, authorisation failures, and sensitive operations. Include: who, what, when, from where, and outcome. Store logs in a tamper-evident, centralised system. Retain logs per compliance requirements.'),

  ('NIST-IA-5', 'Authenticator Management',
   'The system manages information system authenticators (passwords, tokens, keys) securely.',
   'HIGH', ARRAY['all'], 'CWE-287',
   'Look for password storage without hashing, use of MD5/SHA1 for password hashing, hardcoded credentials, long-lived tokens without rotation, API keys stored in plaintext config or source code. Check for password reset tokens without expiry.',
   'Use bcrypt, argon2, or scrypt for password hashing with appropriate work factor. Rotate credentials regularly. Store secrets in a secrets manager. Enforce password complexity and minimum length. Expire password reset tokens within 1 hour.'),

  ('NIST-SC-8', 'Transmission Confidentiality and Integrity',
   'The system protects the confidentiality and integrity of transmitted information.',
   'HIGH', ARRAY['all'], 'CWE-319',
   'Look for HTTP endpoints serving or accepting sensitive data. Check for SSL/TLS verification disabled in HTTP clients. Look for weak cipher suites in TLS configuration. Check for sensitive data in URL query parameters (logged by proxy servers). Check for WebSocket connections without TLS.',
   'Enforce TLS 1.2+ on all transmission. Set HSTS. Never disable certificate verification. Avoid sensitive data in URLs. Use secure, encrypted WebSocket (wss://) connections.'),

  ('NIST-SI-10', 'Information Input Validation',
   'The system checks the validity of information inputs.',
   'HIGH', ARRAY['all'], 'CWE-20',
   'Look for missing server-side input validation on all user-supplied data. Check for validation that only occurs client-side (JavaScript). Look for unvalidated file uploads, missing content-type checks, missing length limits on string inputs. Check for deserialization of unvalidated input.',
   'Validate all inputs server-side, regardless of client-side validation. Use allowlists over denylists. Validate type, length, format, and range. Reject invalid inputs early before processing.')

) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'NIST'
ON CONFLICT DO NOTHING;


-- ============================================================
-- PCI-DSS 4.0 (focused on code-auditable requirements)
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'team'
FROM frameworks f,
(VALUES
  ('PCI-6.2.4', 'Software Attacks Prevention',
   'Software development practices prevent or mitigate common software attacks.',
   'CRITICAL', ARRAY['all'], 'CWE-89',
   'Look for SQL injection risks (string concatenation in queries), XSS vulnerabilities (unencoded output in HTML), command injection (shell=True with user input), path traversal (user input in file paths), SSRF (user-controlled URLs in HTTP requests). Check for missing parameterisation in any interpreter call.',
   'Apply OWASP secure coding guidelines. Use parameterised queries. HTML-encode all output. Use shell=False. Validate and sanitise all inputs. Implement a secure development lifecycle with code review gates.'),

  ('PCI-6.3.2', 'Inventory of Bespoke and Custom Software',
   'An inventory of bespoke and custom software is maintained to support vulnerability management.',
   'LOW', ARRAY['all'], NULL,
   'Look for third-party library usage without version pinning. Check for direct use of libraries with known CVEs. Look for dependencies pulled from unverified sources. Check for absence of a software composition analysis (SCA) tool integration.',
   'Maintain a software bill of materials (SBOM). Pin all dependency versions. Run SCA tools (Dependabot, Snyk) in CI. Track and remediate CVEs in dependencies promptly.'),

  ('PCI-8.3.6', 'Strong Authentication for User Accounts',
   'Passwords and passphrases for user accounts meet PCI-DSS minimum complexity requirements.',
   'HIGH', ARRAY['all'], 'CWE-521',
   'Look for password validation that allows passwords shorter than 12 characters. Check for missing complexity requirements (mixed case, numbers, special characters). Look for passwords stored without hashing or hashed with MD5/SHA1. Check for hardcoded credentials or default passwords.',
   'Enforce minimum 12-character passwords with complexity. Hash with bcrypt (cost >= 12) or argon2id. Prohibit commonly-used passwords. Force password change on first login and after breach notification.'),

  ('PCI-8.6.1', 'Inactive Account Management',
   'Accounts inactive for more than 90 days are removed or disabled.',
   'MEDIUM', ARRAY['all'], 'CWE-613',
   'Look for session tokens without expiry. Check for long-lived API keys without rotation policy. Look for missing last-login tracking. Check for "remember me" implementations with multi-year expiry. Look for service accounts with non-expiring passwords.',
   'Implement session expiry (idle timeout + absolute maximum). Rotate API keys regularly. Track last login and disable inactive accounts. Set short expiry on all tokens. Implement token revocation.'),

  ('PCI-3.4.1', 'PAN Masking',
   'Primary Account Numbers (PAN) must be masked when displayed — only the first 6 and last 4 digits may be shown.',
   'CRITICAL', ARRAY['all'], 'CWE-200',
   'Look for credit card numbers (16-digit sequences matching Luhn) being logged, stored in plaintext, returned in full in API responses, or displayed without masking. Check for card data appearing in error messages, debug logs, or URL parameters.',
   'Never log, store, or display full PANs. Use tokenisation for payment processing. Mask to first 6 / last 4 in all display contexts. Use PCI-compliant payment processors (Stripe, Braintree) to avoid handling raw card data.'),

  ('PCI-6.4.1', 'Web-Facing Application Protection',
   'Public-facing web applications are protected against known web-based attacks.',
   'HIGH', ARRAY['all'], 'CWE-284',
   'Look for missing CSRF protection on state-changing operations. Check for missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options). Look for clickjacking vulnerabilities (missing frame-busting). Check for verbose error messages revealing implementation details to end users.',
   'Set all OWASP-recommended security headers. Implement CSRF tokens or SameSite cookies. Use a WAF for public-facing applications. Return generic error messages. Enable logging and alerting on attack patterns.')

) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'PCIDSS'
ON CONFLICT DO NOTHING;


-- ============================================================
-- Language-specific CWE variants
-- More precise hints for the highest-value rules, per language
-- ============================================================
INSERT INTO rules (framework_id, code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance, plan_tier)
SELECT f.id, r.code, r.title, r.description, r.severity, r.languages, r.cwe_id, r.prompt_hints, r.fix_guidance, 'developer'
FROM frameworks f,
(VALUES
  ('CWE-89-PY', 'SQL Injection (Python)',
   'Python-specific patterns: f-strings, % formatting, and .format() used in SQL queries.',
   'CRITICAL', ARRAY['python'], 'CWE-89',
   'Look for: cursor.execute(f"SELECT ... {var}"), cursor.execute("SELECT ... %s" % var), cursor.execute("SELECT ... {}".format(var)), any SQLAlchemy text() call with string formatting, Django ORM raw() with interpolated input.',
   'Use cursor.execute("SELECT ... WHERE id = %s", (user_id,)) — always tuple second argument. In SQLAlchemy use bindparams. In Django use ORM queries or parameterised raw() with params argument.'),

  ('CWE-89-JS', 'SQL Injection (JavaScript/TypeScript)',
   'JavaScript-specific patterns: template literals and string concatenation in database queries.',
   'CRITICAL', ARRAY['javascript', 'typescript'], 'CWE-89',
   'Look for: db.query(`SELECT ... ${userInput}`), db.query("SELECT ... " + userInput), Knex.raw() with template literals, Sequelize.query() with interpolated strings, mongoose $where with user input, any pool.execute() with concatenated strings.',
   'Use parameterised queries: db.query("SELECT ... WHERE id = ?", [userId]). In Knex use .where({id: userId}). In TypeORM use :param syntax with parameters object. Never use template literals or concatenation in SQL strings.'),

  ('CWE-89-JAVA', 'SQL Injection (Java)',
   'Java-specific patterns: Statement vs PreparedStatement, JDBC string concatenation.',
   'CRITICAL', ARRAY['java'], 'CWE-89',
   'Look for: Statement (not PreparedStatement) used with concatenated input, PreparedStatement with concatenated strings instead of setString/setInt, JPA createNativeQuery() with string interpolation, JPQL with concatenated predicates, MyBatis ${}  interpolation (vs #{} parameterisation).',
   'Always use PreparedStatement with setString()/setInt() etc. In JPA/JPQL use named parameters (:param) with setParameter(). In MyBatis use #{} not ${}. Never concatenate user input into any SQL string.'),

  ('CWE-78-PY', 'OS Command Injection (Python)',
   'Python-specific patterns for shell command injection.',
   'CRITICAL', ARRAY['python'], 'CWE-78',
   'Look for: subprocess.call(shell=True) with user input, subprocess.Popen(shell=True), os.system() with user input, os.popen(), eval() with user data, exec() with user data, __import__() with user-controlled module name.',
   'Use subprocess.run([cmd, arg1, arg2], shell=False) — pass arguments as a list, never a string. Validate all inputs against an allowlist. Replace os.system() with subprocess. Never use eval() or exec() with external input.'),

  ('CWE-79-JS', 'Cross-Site Scripting (JavaScript/TypeScript)',
   'JavaScript-specific XSS patterns in both frontend and server-side rendering.',
   'HIGH', ARRAY['javascript', 'typescript'], 'CWE-79',
   'Look for: element.innerHTML = userInput, document.write(userInput), $(selector).html(userInput), dangerouslySetInnerHTML in React, v-html in Vue with unsanitised content, res.send() or res.write() with unescaped user input in Express, template literals in EJS/Handlebars/Pug with unescaped {{{}}},  eval(userInput).',
   'Use textContent instead of innerHTML. In React avoid dangerouslySetInnerHTML; if needed, sanitise with DOMPurify first. In Express use res.json() for data or escape with he/entities library. Enable Content-Security-Policy header. In template engines use escaped output ({{}} not {{{}}}).'),

  ('CWE-502-PY', 'Insecure Deserialization (Python)',
   'Python-specific deserialization vulnerabilities enabling remote code execution.',
   'CRITICAL', ARRAY['python'], 'CWE-502',
   'Look for: pickle.loads(user_data), pickle.load(user_file), cPickle.loads(), yaml.load() without Loader=yaml.SafeLoader, marshal.loads(user_data), shelve accessed with user-controlled keys, jsonpickle.decode() with user input.',
   'Never use pickle/marshal/cPickle with untrusted data — they allow arbitrary code execution. Use yaml.safe_load() not yaml.load(). Use json.loads() for data exchange. If deserialisation is unavoidable, validate the data against a strict schema before deserialising.'),

  ('CWE-611-JAVA', 'XXE Injection (Java)',
   'Java XML parser configurations that enable external entity processing.',
   'HIGH', ARRAY['java'], 'CWE-611',
   'Look for: DocumentBuilderFactory without setFeature("http://apache.org/xml/features/disallow-doctype-decl", true), SAXParserFactory without disabling external entities, XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES=false, JAXB unmarshal with untrusted XML, XPathFactory processing untrusted input.',
   'Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) on all XML factories. Disable external entity processing explicitly. Use a hardened XML parsing utility class across the codebase. Consider switching to JSON where XML is not required.')

) AS r(code, title, description, severity, languages, cwe_id, prompt_hints, fix_guidance)
WHERE f.code = 'CWE'
ON CONFLICT DO NOTHING;


-- ============================================================
-- Update baseline OWASP prompt template to include {rules} placeholder
-- so loaded rules get injected into the prompt
-- ============================================================
UPDATE prompt_templates
SET template = 'You are a senior security engineer conducting a formal code review.

Analyse the following {language} code for security vulnerabilities using the OWASP Top 10 ({frameworks}) framework.
Severity threshold: {severity_threshold} and above only.
{team_context}

Focus specifically on these vulnerability patterns:
{rules}

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
}'
WHERE name = 'Default OWASP Security Scan';
