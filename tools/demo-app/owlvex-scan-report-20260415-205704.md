# Owlvex Vulnerability Scan Report

Generated: 2026-04-15T19:57:04.348Z
Target: `tools/demo-app`
Report location: `d:\Dev\repos\CodeScanner\tools\demo-app`

## Summary

- Files scanned: 15
- Files with findings: 9
- Total findings: 18
- Average score: 6.2/10
- Deterministic findings: 1
- Intelligence source coverage: Bundled Fallback: 15
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Errors: 0
- Scan warnings: 6

## Findings By File

### src\db.js

- Score: 0.0/10
- Findings: 3
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 3 finding(s), led by a critical-impact/high-likelihood Unsanitized SQL query construction (10/10 risk). Primary issue family: Injection & Execution. 2 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Unsanitized SQL query construction | impact critical \| likelihood high \| risk 10/10 | AI 62% |
| Broken Access Control in getDocumentById | impact high \| likelihood high \| risk 9/10 | AI 80% |
| Sensitive data exposed in logs | impact medium \| likelihood medium \| risk 5/10 | AI 68% |

#### Unsanitized SQL query construction
- Location: `src\db.js` at L16-18
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The function findUsersByEmailUnsafe constructs an SQL query using string concatenation with untrusted user input, which can lead to SQL injection attacks.
- What to change: Use parameterized queries to safely handle user input. For example, use a prepared statement with placeholders for user input.
- Why likely: The SQL query directly concatenates user input without validation or sanitization.
- Threat: An attacker could inject malicious SQL code to access or manipulate sensitive data in the database.
- Mappings: CWE: CWE-89 | OWASP: A03 | NIST: SI-10
- STRIDE: Elevation of Privilege
- Matched signals: string concatenation in SQL query
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  15 | function getDocumentForUser(id, userId) {
  16 |   return documents.find((doc) => doc.id === id && doc.ownerId === userId);
  17 | }
  18 | 
  19 | function getDocumentForTenant(id, tenantId) {
```

#### Broken Access Control in getDocumentById
- Location: `src\db.js` at L8-10
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The function getDocumentById allows any user to retrieve any document by its ID without verifying ownership or access permissions.
- What to change: Add authorization checks to ensure that the user has the necessary permissions to access the requested document.
- Why likely: The function does not validate the user's access rights to the document.
- Threat: An attacker could access sensitive documents that they do not own or have permission to view.
- Mappings: CWE: CWE-862 | OWASP: A01 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: missing authorization check for resource access
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   7 |   { id: 'user-1', tenantId: 'tenant-a', email: 'alice@tenant-a.test' },
   8 |   { id: 'user-2', tenantId: 'tenant-b', email: 'bob@tenant-b.test' }
   9 | ];
  10 | 
  11 | function getDocumentById(id) {
```

#### Sensitive data exposed in logs
- Location: `src\db.js` at L8-14
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The document access functions do not implement defense-in-depth mechanisms such as logging access attempts or rate limiting to prevent abuse.
- What to change: Implement logging for access attempts and add rate limiting to prevent abuse.
- Why likely: The lack of logging and rate limiting increases the risk of undetected abuse.
- Threat: An attacker could exploit this to enumerate documents or perform unauthorized access attempts without detection.
- Mappings: CWE: CWE-306 | OWASP: A04 | NIST: AU-2
- STRIDE: Repudiation
- Matched signals: missing logging and rate limiting on access functions
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   7 |   { id: 'user-1', tenantId: 'tenant-a', email: 'alice@tenant-a.test' },
   8 |   { id: 'user-2', tenantId: 'tenant-b', email: 'bob@tenant-b.test' }
   9 | ];
  10 | 
  11 | function getDocumentById(id) {
  12 |   return documents.find((doc) => doc.id === id);
  13 | }
  14 | 
  15 | function getDocumentForUser(id, userId) {
```

### src\lib\tokens.js

- Score: 0.0/10
- Findings: 3
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 3 finding(s), led by a critical-impact/high-likelihood Hardcoded token in source code (10/10 risk). Primary issue family: Secrets & Credential Exposure. 2 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Hardcoded token in source code | impact critical \| likelihood high \| risk 10/10 | AI 100% |
| Weak JWT validation | impact high \| likelihood high \| risk 9/10 | AI 100% |
| Weak JWT validation | impact high \| likelihood medium \| risk 8/10 | AI 90% |

#### Hardcoded token in source code
- Location: `src\lib\tokens.js` at L3
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The secret key 'DEMO_SECRET' is hardcoded in the source code, which makes it vulnerable to exposure and misuse if the source code is leaked or accessed by unauthorized parties.
- What to change: Replace hardcoded bearer tokens, session tokens, and integration tokens with managed secret delivery, and revoke or rotate any token that was exposed in source or build artifacts.
- Safe pattern: Store the secret key in a secure environment variable or a dedicated secret management system, and ensure it is not hardcoded in the source code.
- Validate with: Search the repository, generated bundles, and environment templates to confirm the old token is gone. | Verify integrations still function when the token is loaded from managed configuration. | Confirm the exposed token has been revoked or rotated and cannot be used successfully.
- Avoid: Keeping the token in a checked-in environment file or sample configuration. | Masking part of the token while continuing to ship the usable secret with the application. | Removing the token from source but leaving the compromised token active.
- Why likely: The secret is directly exposed in the source code, making it easily accessible if the code is leaked.
- Threat: An attacker who gains access to the source code can use the hardcoded secret to forge valid JWTs or decrypt sensitive data.
- Mappings: CWE: CWE-798
- STRIDE: Information Disclosure
- Matched signals: DEMO_SECRET
- Sources: OWASP Secrets Management Cheat Sheet, CWE-798 Use of Hard-coded Credentials
- AI grounding: Curated framework pack | OWASP Secrets Management Cheat Sheet
- Code involved in the reasoning:
```text
   2 | 
   3 | const DEMO_SECRET = 'owlvex-demo-secret';
   4 | 
```

#### Weak JWT validation
- Location: `src\lib\tokens.js` at L8-12
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The function 'decodeJwtWithoutVerification' decodes the payload of a JWT without verifying its signature, which allows attackers to tamper with the token and bypass authentication or authorization checks.
- What to change: Verify signature, issuer, audience, expiry, and accepted algorithms on every token, and reject tokens that are unsigned, weakly validated, or trusted only because they exist.
- Safe pattern: Always verify the signature of a JWT before decoding its payload. Use a library that handles both decoding and verification securely.
- Validate with: Test expired, wrong-issuer, wrong-audience, and unexpected-algorithm tokens and confirm each one is rejected. | Add automated tests that prove protected routes fail closed when claim validation is incomplete. | Review authentication middleware configuration to confirm signature and claim validation occur before authorization logic.
- Avoid: Decoding JWTs without verification and treating decoded claims as trusted identity. | Checking expiry alone while skipping issuer, audience, or algorithm validation. | Using the token's declared algorithm as the only source of truth for what to accept.
- Why likely: The function explicitly skips signature verification, making it trivial for an attacker to exploit.
- Threat: An attacker could modify the token payload to impersonate another user or escalate privileges.
- Mappings: CWE: CWE-345
- STRIDE: Spoofing
- Matched signals: decodeJwtWithoutVerification, jwt
- Sources: OWASP JSON Web Token Cheat Sheet for Java, CWE-345 Insufficient Verification of Data Authenticity
- AI grounding: Curated framework pack | OWASP JSON Web Token Cheat Sheet for Java
- Code involved in the reasoning:
```text
   7 | }
   8 | 
   9 | function decodeJwtWithoutVerification(token) {
  10 |   const parts = String(token || '').split('.');
  11 |   if (parts.length !== 3) {
  12 |     throw new Error('token_format_invalid');
  13 |   }
```

#### Weak JWT validation
- Location: `src\lib\tokens.js` at L15-22
- Risk: HIGH impact / MEDIUM likelihood / 8/10
- Why it matters: The function 'verifyJwtHmac' uses a hardcoded secret and manually constructs the HMAC signature for JWT verification. This approach is error-prone and may lead to vulnerabilities if not implemented correctly.
- What to change: Verify signature, issuer, audience, expiry, and accepted algorithms on every token, and reject tokens that are unsigned, weakly validated, or trusted only because they exist.
- Safe pattern: Use a well-tested library for JWT verification, such as 'jsonwebtoken', which handles signature verification and claim validation securely.
- Validate with: Test expired, wrong-issuer, wrong-audience, and unexpected-algorithm tokens and confirm each one is rejected. | Add automated tests that prove protected routes fail closed when claim validation is incomplete. | Review authentication middleware configuration to confirm signature and claim validation occur before authorization logic.
- Avoid: Decoding JWTs without verification and treating decoded claims as trusted identity. | Checking expiry alone while skipping issuer, audience, or algorithm validation. | Using the token's declared algorithm as the only source of truth for what to accept.
- Why likely: The use of a hardcoded secret and manual cryptographic operations increases the risk of implementation errors.
- Threat: An attacker could exploit implementation flaws to forge valid JWTs or bypass authentication.
- Mappings: CWE: CWE-327
- STRIDE: Spoofing
- Matched signals: verifyJwtHmac, createHmac, jwt
- Sources: OWASP JSON Web Token Cheat Sheet for Java, CWE-345 Insufficient Verification of Data Authenticity
- AI grounding: Curated framework pack | OWASP JSON Web Token Cheat Sheet for Java
- Code involved in the reasoning:
```text
  14 | 
  15 |   return decodeSegment(parts[1]);
  16 | }
  17 | 
  18 | function verifyJwtHmac(token) {
  19 |   const parts = String(token || '').split('.');
  20 |   if (parts.length !== 3) {
  21 |     throw new Error('token_format_invalid');
  22 |   }
  23 | 
```

### src\server.js

- Score: 3.3/10
- Findings: 3
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 3 finding(s), led by a high-impact/high-likelihood Cleartext transmission of sensitive data over HTTP (9/10 risk). Primary issue family: Data Protection & Privacy. 2 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Cleartext transmission of sensitive data over HTTP | impact high \| likelihood high \| risk 9/10 | AI 90% |
| Missing CSRF protection on state-changing request | impact medium \| likelihood medium \| risk 5/10 | AI 80% |
| Sensitive data exposed in logs | impact medium \| likelihood medium \| risk 5/10 | AI 80% |

#### Cleartext transmission of sensitive data over HTTP
- Location: `src\server.js` at L31
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The application is configured to listen on HTTP (http://localhost:3030), which transmits data in plaintext. This can expose sensitive information to attackers intercepting network traffic.
- What to change: Require HTTPS with HSTS for all sensitive endpoints and redirect HTTP to HTTPS at the infrastructure layer.
- Safe pattern: Configure the application to use HTTPS with a valid SSL/TLS certificate and enforce HSTS to ensure secure communication.
- Why likely: The application is explicitly configured to use HTTP, which is inherently insecure for transmitting sensitive data.
- Threat: An attacker could intercept sensitive data, such as session cookies or authentication tokens, leading to account compromise or data breaches.
- Mappings: CWE: CWE-311 | OWASP: A02 | NIST: SC-12
- STRIDE: Information Disclosure
- Matched signals: http://
- Sources: OWASP Transport Layer Security Cheat Sheet
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  30 | 
  31 | app.post('/browser/profile-safe', requireCsrf, (req, res) => {
  32 |   res.json({
```

#### Missing CSRF protection on state-changing request
- Location: `src\server.js` at L23
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The application does not enforce CSRF protection on state-changing routes such as '/documents', '/browser', '/integrations', '/uploads', '/search', '/auth', and '/logs'. This could allow attackers to perform unauthorized actions on behalf of authenticated users.
- What to change: Protect state-changing browser requests with anti-CSRF tokens or equivalent same-site defenses, and ensure sensitive actions cannot be triggered cross-origin by ambient browser credentials alone.
- Safe pattern: Implement CSRF protection for all state-changing routes by requiring anti-CSRF tokens or enabling SameSite cookies.
- Validate with: Attempt a cross-site form or request trigger and confirm the state-changing action is rejected without a valid token. | Add tests proving mutating routes fail when cookie-authenticated requests omit or forge the anti-CSRF token. | Review same-site, origin-check, and token behavior across all browser-authenticated state-changing flows.
- Avoid: Relying only on referer checks or client-side JavaScript restrictions. | Disabling CSRF middleware because the route is called by fetch or SPA code. | Treating hidden form fields without server validation as CSRF protection.
- Why likely: The '/browser/profile-safe' route has CSRF protection, but other state-changing routes do not, increasing the risk of exploitation.
- Threat: An attacker could trick a user into performing unintended actions, such as modifying data or changing account settings, without their consent.
- Mappings: CWE: CWE-352 | OWASP: A05 | NIST: AC-3
- STRIDE: Tampering
- Matched signals: csrf
- Sources: OWASP Cross-Site Request Forgery Prevention Cheat Sheet, CWE-352 Cross-Site Request Forgery
- AI grounding: Curated framework pack | OWASP Cross-Site Request Forgery Prevention Cheat Sheet
- Code involved in the reasoning:
```text
  22 | 
  23 | app.use('/documents', documentRoutes);
  24 | app.use('/browser', browserRoutes);
```

#### Sensitive data exposed in logs
- Location: `src\server.js` at L34
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The application logs sensitive data, such as the 'displayName' field from the request body, without sanitization. This could lead to sensitive information being stored in logs.
- What to change: Remove secrets, tokens, credentials, and other sensitive values from logs, traces, and error telemetry, and apply structured redaction so observability output remains useful without leaking protected data.
- Safe pattern: Avoid logging sensitive data directly. If logging is necessary, ensure sensitive fields are redacted or anonymized before logging.
- Validate with: Exercise sensitive flows and confirm logs, traces, and error telemetry do not contain secrets or protected data. | Add tests or log snapshots proving redaction occurs for known sensitive fields and headers. | Review retention and downstream log sinks to ensure historical leakage is addressed where feasible.
- Avoid: Relying on log access controls alone while still emitting raw sensitive values. | Masking only one field while related tokens, headers, or payload fragments remain exposed. | Using debug logging in production for sensitive flows without redaction.
- Why likely: The 'displayName' field is logged directly, which could contain sensitive user information.
- Threat: An attacker with access to the logs could extract sensitive information, leading to privacy violations or further attacks.
- Mappings: CWE: CWE-200 | OWASP: A01 | NIST: SI-10
- STRIDE: Information Disclosure
- Matched signals: log, console.log
- Sources: OWASP Logging Cheat Sheet, CWE-532 Insertion of Sensitive Information into Log File
- AI grounding: Curated framework pack | OWASP Logging Cheat Sheet
- Code involved in the reasoning:
```text
  33 |     updated: true,
  34 |     displayName: req.body.displayName,
  35 |   });
```

### src\routes\browser.js

- Score: 3.8/10
- Findings: 2
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 2 finding(s), led by a high-impact/high-likelihood Open redirect through untrusted destination (9/10 risk). Primary issue family: Security Misconfiguration & Platform Hardening. 1 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Open redirect through untrusted destination | impact high \| likelihood high \| risk 9/10 | AI 90% |
| Reflected cross-site scripting | impact high \| likelihood medium \| risk 8/10 | AI 80% |

#### Open redirect through untrusted destination
- Location: `src\routes\browser.js` at L6-8
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The `req.query.next` parameter is directly used in the `res.redirect` function without validation. This allows an attacker to redirect users to malicious websites.
- What to change: Replace attacker-controlled redirect targets with allow-listed route names or trusted destinations, and ensure user input cannot directly choose arbitrary external navigation targets.
- Safe pattern: Validate and sanitize the `req.query.next` parameter to ensure it only allows safe and expected URLs. Use a whitelist of allowed domains or paths.
- Validate with: Attempt to supply an arbitrary external redirect target and confirm the application rejects it or routes to a safe default. | Add tests for local-only redirect enforcement, allowed-host logic, and malicious external URLs. | Review login, logout, payment, and post-action return flows for the same redirect pattern.
- Avoid: Checking only for a missing protocol while still allowing attacker-controlled hosts. | Trying to strip dangerous substrings from a redirect URL instead of validating the full destination. | Assuming client-side link construction prevents server-side redirect abuse.
- Why likely: The `req.query.next` parameter is directly used without validation | making exploitation straightforward.
- Threat: An attacker can craft a malicious URL that redirects users to a phishing site or other malicious destination, potentially leading to credential theft or other attacks.
- Mappings: OWASP: A01 | NIST: AC-3
- STRIDE: Spoofing
- Matched signals: res.redirect, req.query.next
- Sources: OWASP Unvalidated Redirects and Forwards Cheat Sheet, CWE-601 URL Redirection to Untrusted Site
- AI grounding: Curated framework pack | OWASP Unvalidated Redirects and Forwards Cheat Sheet
- Code involved in the reasoning:
```text
   5 | 
   6 | router.get('/continue-unsafe', (req, res) => {
   7 |   return res.redirect(req.query.next);
   8 | });
   9 | 
```

#### Reflected cross-site scripting
- Location: `src\routes\browser.js` at L14-18
- Risk: HIGH impact / MEDIUM likelihood / 8/10
- Why it matters: The `req.body.displayName` parameter is directly included in the JSON response without sanitization. If this value contains malicious JavaScript, it could lead to reflected XSS attacks.
- What to change: Apply context-appropriate output encoding by default, sanitize rich HTML only when genuinely required, and ensure untrusted data cannot reach HTML, script, URL, or attribute sinks without the right protection for that sink.
- Safe pattern: Sanitize the `req.body.displayName` parameter before including it in the JSON response. Use a library like DOMPurify to remove potentially malicious content.
- Validate with: Replay the payload with script tags or event-handler input and confirm the browser renders inert text or sanitized markup instead of executing code. | Add regression coverage for the exact sink that previously reflected attacker-controlled data. | Review all equivalent render paths to ensure the same encoding or sanitization policy is consistently applied.
- Avoid: Encoding some characters manually while leaving context-specific sinks unprotected. | Trusting framework auto-escaping after explicitly opting out with raw HTML helpers. | Relying on client-side validation alone to keep dangerous markup out of the response.
- Why likely: The risk depends on whether the `displayName` field is user-controlled and whether the response is rendered in a browser.
- Threat: An attacker could inject malicious JavaScript into the `displayName` field, which would execute in the browser of any user viewing the response.
- Mappings: OWASP: A03 | NIST: SI-10
- STRIDE: Information Disclosure
- Matched signals: res.json, req.body.displayName
- Sources: OWASP Cross Site Scripting Prevention Cheat Sheet, CWE-79 Improper Neutralization of Input During Web Page Generation
- AI grounding: Curated framework pack | OWASP Cross Site Scripting Prevention Cheat Sheet
- Code involved in the reasoning:
```text
  13 |   } catch (_error) {
  14 |     return res.status(400).json({ error: 'redirect_target_blocked' });
  15 |   }
  16 | });
  17 | 
  18 | router.post('/profile-unsafe', (req, res) => {
  19 |   res.json({
```

### src\routes\integrations.js

- Score: 4.0/10
- Findings: 1
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 1 finding(s), led by a critical-impact/high-likelihood Server-side request forgery through untrusted destination (10/10 risk). Primary issue family: Injection & Execution.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Server-side request forgery through untrusted destination | impact critical \| likelihood high \| risk 10/10 | AI 95% |

#### Server-side request forgery through untrusted destination
- Location: `src\routes\integrations.js` at L7-11
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The '/fetch-unsafe' endpoint directly uses user-supplied input from 'req.query.url' to make an HTTP request without validating or sanitizing the URL. This allows attackers to craft malicious URLs to access internal services or sensitive resources.
- What to change: Constrain outbound requests to approved destinations, normalize and validate URLs before use, and block internal address ranges, metadata endpoints, and attacker-controlled protocols from request execution paths.
- Safe pattern: Validate and sanitize the 'url' parameter to ensure it adheres to a strict allowlist of safe domains or patterns. Use a utility function like 'isAllowedOutboundUrl' to enforce this validation.
- Validate with: Test internal-address and metadata-endpoint payloads and confirm the server rejects them before any outbound request occurs. | Add regression tests for redirects, alternate IP encodings, and unexpected protocols. | Review outbound request helpers to confirm hostname and resolved-IP validation occur in one consistent path.
- Avoid: Checking only for `http` or `https` while allowing arbitrary hosts. | Allow-listing hostnames without validating final resolved IPs or redirects. | Relying on client-side URL restrictions to keep server-side fetches safe.
- Why likely: The 'url' parameter is directly used in an HTTP request without validation. | The endpoint is accessible to authenticated users, increasing the risk of exploitation.
- Threat: An attacker could exploit this vulnerability to perform SSRF attacks, potentially accessing internal services, metadata endpoints, or other restricted resources.
- Mappings: CWE: CWE-918 | ATT&CK: T1190
- STRIDE: Elevation of Privilege
- Matched signals: user-controlled URL in HTTP request
- Sources: OWASP Server Side Request Forgery Prevention Cheat Sheet, CWE-918 Server-Side Request Forgery
- AI grounding: Curated framework pack | OWASP Server Side Request Forgery Prevention Cheat Sheet
- Code involved in the reasoning:
```text
   6 | 
   7 | router.get('/fetch-unsafe', requireAdmin, async (req, res) => {
   8 |   const response = await fetch(req.query.url);
   9 |   const body = await response.text();
  10 |   res.json({ ok: true, body });
  11 | });
  12 | 
```

### src\routes\search.js

- Score: 4.0/10
- Findings: 1
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 1 finding(s), led by a critical-impact/high-likelihood Unsanitized SQL query construction (10/10 risk). Primary issue family: Injection & Execution.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Unsanitized SQL query construction | impact critical \| likelihood high \| risk 10/10 | AI 95% |

#### Unsanitized SQL query construction
- Location: `src\routes\search.js` at L7-9
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The 'findUsersByEmailUnsafe' function is called with user input from 'req.query.email' without any sanitization or parameterization. This allows attackers to inject malicious SQL code, potentially leading to unauthorized data access or database corruption.
- What to change: Separate query structure from untrusted data with parameter binding or ORM-safe APIs, constrain dynamic query parts to allow-lists, and verify that attacker-controlled input can no longer change SQL semantics.
- Safe pattern: Use parameterized queries or prepared statements to safely handle user input. Avoid directly concatenating user input into SQL queries.
- Validate with: Run the vulnerable request with SQL metacharacters and confirm the query still behaves as a normal data lookup. | Add a regression test that passes attacker-controlled input into the same code path and asserts parameter binding is used. | Review logging or query traces to confirm untrusted input is emitted as data values, not merged into SQL text.
- Avoid: Escaping quotes manually instead of using parameterized execution. | Relying on client-side validation or hidden form fields to keep SQL safe. | Switching to a different query string template without changing the dataflow model.
- Why likely: The code directly passes user input into a database query without validation or sanitization. | The endpoint is publicly accessible, increasing the likelihood of exploitation.
- Threat: An attacker can execute arbitrary SQL commands, exfiltrate sensitive data, or modify the database.
- Mappings: CWE: CWE-89 | ATT&CK: T1190 | NIST: SI-10, AC-3
- STRIDE: Elevation of Privilege
- Matched signals: query
- Sources: OWASP SQL Injection Prevention Cheat Sheet, CWE-89 Improper Neutralization of Special Elements used in an SQL Command
- AI grounding: Curated framework pack | OWASP SQL Injection Prevention Cheat Sheet
- Code involved in the reasoning:
```text
   6 | router.get('/users-unsafe', (req, res) => {
   7 |   const result = findUsersByEmailUnsafe(req.query.email);
   8 |   res.json(result);
   9 | });
  10 | 
```

### src\lib\urlPolicy.js

- Score: 5.5/10
- Findings: 3
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 3 finding(s), led by a medium-impact/medium-likelihood Potential Insecure Design in URL Validation (5/10 risk). 2 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Potential Insecure Design in URL Validation | impact medium \| likelihood medium \| risk 5/10 | AI 90% |
| Sensitive data exposed in logs | impact medium \| likelihood medium \| risk 5/10 | AI 78% |
| Potential Insecure Design in Outbound URL Validation | impact medium \| likelihood medium \| risk 5/10 | AI 90% |

#### Potential Insecure Design in URL Validation
- Location: `src\lib\urlPolicy.js` at L6-9
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The `resolveSafeRedirect` function validates the host but does not account for potential bypasses using encoded characters or subdomains. This could allow attackers to redirect users to malicious sites.
- What to change: Normalize and validate the hostname after decoding it and ensure subdomain checks are explicitly handled. For example, use `parsed.hostname` instead of `parsed.host` and verify against the allowlist.
- Why likely: The code uses an allowlist, which is a good practice, but it does not account for potential bypasses using encoded characters or subdomains.
- Threat: An attacker could craft a malicious URL that bypasses the allowlist check, leading to potential phishing or other attacks.
- Mappings: CWE: CWE-601 | OWASP: A04 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: URL validation, allowlist, redirect
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   5 |   const parsed = new URL(target, 'https://app.owlvex.test');
   6 |   if (!SAFE_REDIRECT_HOSTS.has(parsed.host)) {
   7 |     throw new Error('redirect_target_blocked');
   8 |   }
   9 |   return parsed.toString();
  10 | }
```

#### Sensitive data exposed in logs
- Location: `src\lib\urlPolicy.js` at L6-14
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The functions `resolveSafeRedirect` and `isAllowedOutboundUrl` perform security-sensitive operations but do not log any information about blocked or allowed actions. This makes it difficult to audit or investigate potential misuse.
- What to change: Add logging for both allowed and blocked actions, including the target URL and the reason for blocking. Ensure sensitive data is not logged.
- Why likely: The lack of logging is a common oversight, and the functions are performing security-sensitive checks.
- Threat: Without logging, it is harder to detect and investigate unauthorized access attempts or misuse of the application.
- Mappings: OWASP: A04 | NIST: AU-2
- STRIDE: Repudiation
- Matched signals: missing logging, security-sensitive operation
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   5 |   const parsed = new URL(target, 'https://app.owlvex.test');
   6 |   if (!SAFE_REDIRECT_HOSTS.has(parsed.host)) {
   7 |     throw new Error('redirect_target_blocked');
   8 |   }
   9 |   return parsed.toString();
  10 | }
  11 | 
  12 | function isAllowedOutboundUrl(target) {
  13 |   const parsed = new URL(target);
  14 |   return SAFE_FETCH_HOSTS.has(parsed.host);
  15 | }
```

#### Potential Insecure Design in Outbound URL Validation
- Location: `src\lib\urlPolicy.js` at L12-14
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The `isAllowedOutboundUrl` function validates the host but does not account for potential bypasses using encoded characters or subdomains. This could allow attackers to make unauthorized requests to malicious hosts.
- What to change: Normalize and validate the hostname after decoding it and ensure subdomain checks are explicitly handled. For example, use `parsed.hostname` instead of `parsed.host` and verify against the allowlist.
- Why likely: The code uses an allowlist, which is a good practice, but it does not account for potential bypasses using encoded characters or subdomains.
- Threat: An attacker could craft a malicious URL that bypasses the allowlist check, leading to unauthorized outbound requests.
- Mappings: CWE: CWE-601 | OWASP: A04 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: URL validation, allowlist, outbound request
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  11 | 
  12 | function isAllowedOutboundUrl(target) {
  13 |   const parsed = new URL(target);
  14 |   return SAFE_FETCH_HOSTS.has(parsed.host);
  15 | }
```

### src\lib\logger.js

- Score: 6.3/10
- Findings: 1
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 1 finding(s), led by a high-impact/high-likelihood Sensitive data exposed in logs (9/10 risk). Primary issue family: Data Protection & Privacy.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Sensitive data exposed in logs | impact high \| likelihood high \| risk 9/10 | Deterministic `DP-001` |

#### Sensitive data exposed in logs
- Location: `src\lib\logger.js` at L2
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: A logging call includes a sensitive field (`password`) in its arguments. Log output is typically persisted in log aggregation systems that may be accessible to operations staff, third-party vendors, or attackers who gain log access.
- What to change: Remove secrets, tokens, credentials, and other sensitive values from logs, traces, and error telemetry, and apply structured redaction so observability output remains useful without leaking protected data.
- Safe pattern: Remove sensitive fields from log arguments. If diagnostic context is required, log a masked representation (e.g., presence/absence of a token, last 4 digits of a card) rather than the raw value.
- Validate with: Exercise sensitive flows and confirm logs, traces, and error telemetry do not contain secrets or protected data. | Add tests or log snapshots proving redaction occurs for known sensitive fields and headers. | Review retention and downstream log sinks to ensure historical leakage is addressed where feasible.
- Avoid: Relying on log access controls alone while still emitting raw sensitive values. | Masking only one field while related tokens, headers, or payload fragments remain exposed. | Using debug logging in production for sensitive flows without redaction.
- Why likely: The log statement exposes a high-value credential or token field directly.
- Threat: Sensitive fields written to logs can be harvested by anyone with log access, including aggregation platforms, SIEM systems, and external log vendors.
- Mappings: CWE: CWE-532 | OWASP: A09:2021 | ATT&CK: T1005 | NIST: AU-9, SC-28
- STRIDE: Information Disclosure, Repudiation
- Sources: OWASP Logging Cheat Sheet, CWE-532 Insertion of Sensitive Information into Log File
- Code involved in the reasoning:
```text
   1 | function logAuthEventUnsafe(logger, session, password) {
   2 |   logger.info('login_attempt', {
   3 |     userId: session.userId,
```

### src\middleware\csrf.js

- Score: 6.3/10
- Findings: 1
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 1 finding(s), led by a high-impact/high-likelihood Hardcoded token in source code (9/10 risk). Primary issue family: Secrets & Credential Exposure.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Hardcoded token in source code | impact high \| likelihood high \| risk 9/10 | AI 90% |

#### Hardcoded token in source code
- Location: `src\middleware\csrf.js` at L3
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The CSRF token is hardcoded as 'known-good-demo-token', which is a cryptographic failure. Hardcoding sensitive values like tokens in source code makes them predictable and vulnerable to discovery by attackers.
- What to change: Replace hardcoded bearer tokens, session tokens, and integration tokens with managed secret delivery, and revoke or rotate any token that was exposed in source or build artifacts.
- Safe pattern: Generate a unique CSRF token for each user session and validate it server-side. Store the token securely and ensure it is transmitted over HTTPS.
- Validate with: Search the repository, generated bundles, and environment templates to confirm the old token is gone. | Verify integrations still function when the token is loaded from managed configuration. | Confirm the exposed token has been revoked or rotated and cannot be used successfully.
- Avoid: Keeping the token in a checked-in environment file or sample configuration. | Masking part of the token while continuing to ship the usable secret with the application. | Removing the token from source but leaving the compromised token active.
- Why likely: The hardcoded token is easily discoverable and can be exploited without requiring significant effort.
- Threat: An attacker could easily bypass CSRF protection by using the hardcoded token, leading to unauthorized actions on behalf of users.
- Mappings: OWASP: A02 | NIST: IA-5
- STRIDE: Tampering
- Matched signals: hardcoded token
- Sources: OWASP Secrets Management Cheat Sheet, CWE-798 Use of Hard-coded Credentials
- AI grounding: Curated framework pack | OWASP Secrets Management Cheat Sheet
- Code involved in the reasoning:
```text
   2 |   const token = req.headers['x-csrf-token'];
   3 |   if (!token || token !== 'known-good-demo-token') {
   4 |     return res.status(403).json({ error: 'csrf_invalid' });
```

## Scan Warnings

- src\lib\uploadPolicy.js: AI provider unavailable: Azure Foundry error: 429
- src\middleware\auth.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\auth.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\documents.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\logs.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\uploads.js: AI provider unavailable: Azure Foundry error: 429
