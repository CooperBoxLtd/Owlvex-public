# Owlvex Vulnerability Scan Report

Generated: 2026-04-15T19:27:33.545Z
Target: `tools/demo-app`
Report location: `d:\Dev\repos\CodeScanner\tools\demo-app`

## Summary

- Files scanned: 15
- Files with findings: 6
- Total findings: 15
- Average score: 6.8/10
- Deterministic findings: 2
- Intelligence source coverage: Bundled Fallback: 15
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Errors: 0
- Scan warnings: 9

## Findings By File

### src\db.js

- Score: 0.0/10
- Findings: 4
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 4 finding(s), led by a critical-impact/high-likelihood Unsanitized SQL query construction (10/10 risk). Primary issue family: Injection & Execution. 3 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Unsanitized SQL query construction | impact critical \| likelihood high \| risk 10/10 | AI 62% |
| Broken Access Control in getDocumentById | impact high \| likelihood high \| risk 9/10 | AI 90% |
| Broken Access Control in getDocumentForTenant | impact high \| likelihood high \| risk 9/10 | AI 90% |
| Unsafe SQL query in findUsersByEmailUnsafe | impact high \| likelihood high \| risk 9/10 | AI 100% |

#### Unsanitized SQL query construction
- Location: `src\db.js` at L17-21
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The function `findUsersByEmailUnsafe` constructs an SQL query by concatenating user input directly into the query string, which makes it vulnerable to SQL injection attacks.
- What to change: Use parameterized queries or prepared statements to safely handle user input. For example, use `SELECT id, email FROM users WHERE email = ?` with a parameterized value.
- Why likely: Direct concatenation of user input into SQL query without sanitization or parameterization.
- Threat: An attacker could inject malicious SQL code to access or manipulate sensitive data in the database.
- Mappings: CWE: CWE-89 | OWASP: A03 | NIST: SI-10
- STRIDE: Elevation of Privilege
- Matched signals: string concatenation in SQL query
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  16 |   return documents.find((doc) => doc.id === id && doc.ownerId === userId);
  17 | }
  18 | 
  19 | function getDocumentForTenant(id, tenantId) {
  20 |   return documents.find((doc) => doc.id === id && doc.tenantId === tenantId);
  21 | }
  22 | 
```

#### Broken Access Control in getDocumentById
- Location: `src\db.js` at L9-11
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The `getDocumentById` function retrieves a document by its ID without verifying the user's authorization to access it. This could allow unauthorized users to access sensitive documents.
- What to change: Add an authorization check to ensure the user has the necessary permissions to access the requested document.
- Why likely: No ownership or role validation is performed before returning the document.
- Threat: An attacker could access documents they are not authorized to view by providing a valid document ID.
- Mappings: CWE: CWE-862 | OWASP: A01 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: Missing authorization check for resource access
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   8 |   { id: 'user-2', tenantId: 'tenant-b', email: 'bob@tenant-b.test' }
   9 | ];
  10 | 
  11 | function getDocumentById(id) {
  12 |   return documents.find((doc) => doc.id === id);
```

#### Broken Access Control in getDocumentForTenant
- Location: `src\db.js` at L13-15
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The `getDocumentForTenant` function retrieves a document by its ID and tenant ID without verifying the user's authorization to access it. This could allow unauthorized users to access sensitive documents within the same tenant.
- What to change: Add an authorization check to ensure the user belongs to the tenant and has the necessary permissions to access the requested document.
- Why likely: No user-to-tenant relationship validation is performed before returning the document.
- Threat: An attacker could access documents they are not authorized to view by providing a valid document ID and tenant ID.
- Mappings: CWE: CWE-862 | OWASP: A01 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: Missing authorization check for tenant-based resource access
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  12 |   return documents.find((doc) => doc.id === id);
  13 | }
  14 | 
  15 | function getDocumentForUser(id, userId) {
  16 |   return documents.find((doc) => doc.id === id && doc.ownerId === userId);
```

#### Unsafe SQL query in findUsersByEmailUnsafe
- Location: `src\db.js` at L17-21
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The `findUsersByEmailUnsafe` function constructs an SQL query using string concatenation, which is vulnerable to SQL injection attacks.
- What to change: Use parameterized queries or prepared statements to safely handle user input. For example, use `SELECT id, email FROM users WHERE email = ?` with a parameterized value.
- Why likely: Direct concatenation of user input into SQL query without sanitization or parameterization.
- Threat: An attacker could execute arbitrary SQL commands, potentially exposing or modifying sensitive user data.
- Mappings: CWE: CWE-89 | OWASP: A03 | NIST: SI-10
- STRIDE: Elevation of Privilege
- Matched signals: string concatenation in SQL query
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  16 |   return documents.find((doc) => doc.id === id && doc.ownerId === userId);
  17 | }
  18 | 
  19 | function getDocumentForTenant(id, tenantId) {
  20 |   return documents.find((doc) => doc.id === id && doc.tenantId === tenantId);
  21 | }
  22 | 
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
| Weak JWT validation | impact critical \| likelihood high \| risk 10/10 | AI 100% |
| Weak or deprecated cryptographic primitive | impact high \| likelihood medium \| risk 8/10 | AI 90% |

#### Hardcoded token in source code
- Location: `src\lib\tokens.js` at L3
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The secret key 'DEMO_SECRET' is hardcoded in the source code, which makes it vulnerable to exposure if the source code is leaked. Hardcoded secrets are a common source of credential leaks.
- What to change: Replace hardcoded bearer tokens, session tokens, and integration tokens with managed secret delivery, and revoke or rotate any token that was exposed in source or build artifacts.
- Safe pattern: Store the secret key in a secure environment variable or a dedicated secret management system, and remove it from the source code.
- Validate with: Search the repository, generated bundles, and environment templates to confirm the old token is gone. | Verify integrations still function when the token is loaded from managed configuration. | Confirm the exposed token has been revoked or rotated and cannot be used successfully.
- Avoid: Keeping the token in a checked-in environment file or sample configuration. | Masking part of the token while continuing to ship the usable secret with the application. | Removing the token from source but leaving the compromised token active.
- Why likely: The secret is directly exposed in the source code, making it trivial for an attacker to exploit if the code is leaked.
- Threat: An attacker who gains access to the source code can use the hardcoded secret to forge valid JWTs or decrypt sensitive data.
- Mappings: OWASP: A02 | NIST: IA-5
- STRIDE: Information Disclosure
- Matched signals: hardcoded_secret
- Sources: OWASP Secrets Management Cheat Sheet, CWE-798 Use of Hard-coded Credentials
- AI grounding: Curated framework pack | OWASP Secrets Management Cheat Sheet
- Code involved in the reasoning:
```text
   2 | 
   3 | const DEMO_SECRET = 'owlvex-demo-secret';
   4 | 
```

#### Weak JWT validation
- Location: `src\lib\tokens.js` at L9-15
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The function 'decodeJwtWithoutVerification' decodes the payload of a JWT without verifying its signature. This allows attackers to tamper with the token and bypass authentication or authorization checks.
- What to change: Verify signature, issuer, audience, expiry, and accepted algorithms on every token, and reject tokens that are unsigned, weakly validated, or trusted only because they exist.
- Safe pattern: Always verify the JWT signature using a secure library before decoding and trusting its contents.
- Validate with: Test expired, wrong-issuer, wrong-audience, and unexpected-algorithm tokens and confirm each one is rejected. | Add automated tests that prove protected routes fail closed when claim validation is incomplete. | Review authentication middleware configuration to confirm signature and claim validation occur before authorization logic.
- Avoid: Decoding JWTs without verification and treating decoded claims as trusted identity. | Checking expiry alone while skipping issuer, audience, or algorithm validation. | Using the token's declared algorithm as the only source of truth for what to accept.
- Why likely: The function explicitly skips signature verification, making it highly exploitable if used in a security-sensitive context.
- Threat: An attacker could modify the JWT payload to impersonate another user or escalate privileges without detection.
- Mappings: OWASP: A07 | NIST: IA-5
- STRIDE: Spoofing
- Matched signals: jwt_decode_without_verification
- Sources: OWASP JSON Web Token Cheat Sheet for Java, CWE-345 Insufficient Verification of Data Authenticity
- AI grounding: Curated framework pack | OWASP JSON Web Token Cheat Sheet for Java
- Code involved in the reasoning:
```text
   8 | 
   9 | function decodeJwtWithoutVerification(token) {
  10 |   const parts = String(token || '').split('.');
  11 |   if (parts.length !== 3) {
  12 |     throw new Error('token_format_invalid');
  13 |   }
  14 | 
  15 |   return decodeSegment(parts[1]);
  16 | }
```

#### Weak or deprecated cryptographic primitive
- Location: `src\lib\tokens.js` at L17-33
- Risk: HIGH impact / MEDIUM likelihood / 8/10
- Why it matters: The code uses HMAC with SHA-256 for JWT signature verification, but the secret key is hardcoded and not securely managed. This weakens the overall cryptographic security.
- What to change: Replace broken or deprecated algorithms with modern approved primitives and secure modes, and centralize cryptographic choices so insecure defaults cannot linger in isolated code paths.
- Safe pattern: Use a securely stored and rotated secret key, and consider using a library like jsonwebtoken to handle JWT signing and verification securely.
- Validate with: Review the final code path and configuration to confirm deprecated algorithms and modes are no longer present. | Add tests or checks that assert the expected modern algorithms are selected in security-sensitive paths. | Review compatibility or migration code to ensure it does not silently re-enable weak cryptography.
- Avoid: Wrapping a weak primitive in more code instead of replacing it. | Keeping deprecated algorithms for convenience without hard migration boundaries. | Changing one call site while leaving the same weak algorithm active elsewhere in the stack.
- Why likely: The use of SHA-256 is secure, but the hardcoded secret key significantly increases the risk of exploitation.
- Threat: An attacker who obtains the hardcoded secret can forge valid JWTs, compromising the integrity of the authentication system.
- Mappings: OWASP: A02 | NIST: SC-12
- STRIDE: Tampering
- Matched signals: weak_hmac_key
- Sources: OWASP Cryptographic Storage Cheat Sheet, CWE-327 Use of a Broken or Risky Cryptographic Algorithm
- AI grounding: Curated framework pack | OWASP Cryptographic Storage Cheat Sheet
- Code involved in the reasoning:
```text
  16 | }
  17 | 
  18 | function verifyJwtHmac(token) {
  19 |   const parts = String(token || '').split('.');
  20 |   if (parts.length !== 3) {
  21 |     throw new Error('token_format_invalid');
  22 |   }
  23 | 
  24 |   const [header, payload, signature] = parts;
  25 |   const expected = crypto
  26 |     .createHmac('sha256', DEMO_SECRET)
  27 |     .update(`${header}.${payload}`)
  28 |     .digest('base64url');
  29 | 
  30 |   if (signature !== expected) {
  31 |     throw new Error('signature_invalid');
  32 |   }
  33 | 
  34 |   const claims = decodeSegment(payload);
```

### src\routes\uploads.js

- Score: 1.5/10
- Findings: 2
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 2 finding(s), led by a critical-impact/high-likelihood Untrusted filesystem path traversal (10/10 risk). Primary issue family: Access Control & Authorization. 1 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Untrusted filesystem path traversal | impact critical \| likelihood high \| risk 10/10 | AI 90% |
| Verbose error disclosure to clients | impact high \| likelihood medium \| risk 8/10 | AI 80% |

#### Untrusted filesystem path traversal
- Location: `src\routes\uploads.js` at L7-9
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The 'buildUploadPath' function is used to construct a file path directly from user input without validation or sanitization. This allows an attacker to craft a malicious fileName containing '../' to write files outside the intended directory.
- What to change: Constrain file access to a fixed base directory, normalize and resolve paths before use, and reject any request-derived path that escapes the allowed boundary or selects unexpected files.
- Safe pattern: Validate and sanitize the 'fileName' input to ensure it does not contain directory traversal sequences (e.g., '../'). Use a fixed base directory and resolve paths against it to prevent traversal.
- Validate with: Test traversal payloads such as `../`, encoded traversal, and platform-specific separators and confirm the request is rejected. | Add regression tests that assert resolved paths always remain under the intended storage root. | Review adjacent archive, upload, download, and temp-file code paths for the same normalization and boundary-check rules.
- Avoid: Removing only a few traversal tokens while still accepting arbitrary paths. | Checking string prefixes before normalization or canonical resolution. | Assuming UI constraints or route structure prevent malicious path input from reaching the filesystem.
- Why likely: The 'buildUploadPath' function is not shown, so its implementation cannot be verified. | The code directly uses user input ('req.body.fileName') without validation, making exploitation highly likely.
- Threat: An attacker could overwrite or create arbitrary files on the server, potentially leading to data corruption, privilege escalation, or remote code execution.
- Mappings: CWE: CWE-22
- STRIDE: Elevation of Privilege
- Matched signals: ../
- Sources: OWASP Path Traversal, CWE-22 Improper Limitation of a Pathname to a Restricted Directory
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
   6 | 
   7 | router.post('/unsafe', (req, res) => {
   8 |   const targetPath = buildUploadPath(req.body.fileName);
   9 |   fs.writeFileSync(targetPath, req.body.contents, 'utf8');
  10 |   res.json({ stored: true, path: targetPath });
```

#### Verbose error disclosure to clients
- Location: `src\routes\uploads.js` at L14-16
- Risk: HIGH impact / MEDIUM likelihood / 8/10
- Why it matters: The '/safe' endpoint returns the full error message to the client in case of an exception. This could expose sensitive internal details about the application, such as file paths or stack traces.
- What to change: Return generic client-facing errors for untrusted callers, keep stack traces and internal diagnostics out of responses, and route detailed failure data to protected logs or telemetry instead.
- Safe pattern: Replace the detailed error message with a generic error message for the client, and log the detailed error message to a secure server-side log for debugging purposes.
- Validate with: Trigger representative failures and confirm responses do not reveal stack traces, internal paths, config values, or sensitive implementation details. | Verify detailed diagnostics are still available in protected logs or telemetry for operators. | Review production configuration to ensure debug or developer exception modes are disabled.
- Avoid: Hiding only the message text while still returning stack traces or internal object dumps. | Conditionally exposing detailed errors based on easily spoofed request headers or query parameters. | Relying on client-side handling alone while backend APIs continue to leak internal exceptions.
- Why likely: The error message is directly returned to the client, but the impact depends on the specific error details exposed.
- Threat: An attacker could use the exposed error details to gain insights into the application's internal structure, making it easier to exploit other vulnerabilities.
- Mappings: CWE: CWE-209
- STRIDE: Information Disclosure
- Matched signals: error.message
- Sources: OWASP Error Handling Cheat Sheet, CWE-209 Generation of Error Message Containing Sensitive Information
- AI grounding: Curated framework pack | OWASP Error Handling Cheat Sheet
- Code involved in the reasoning:
```text
  13 | router.post('/safe', (req, res) => {
  14 |   try {
  15 |     const targetPath = buildSafeUploadPath(req.body.fileName);
  16 |     fs.writeFileSync(targetPath, req.body.contents, 'utf8');
  17 |     return res.json({ stored: true, path: targetPath });
```

### src\lib\logger.js

- Score: 2.5/10
- Findings: 2
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 2 finding(s), led by a high-impact/high-likelihood Sensitive data exposed in logs (9/10 risk). Primary issue family: Data Protection & Privacy. 1 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Sensitive data exposed in logs | impact high \| likelihood high \| risk 9/10 | Deterministic `DP-001` |
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

#### Sensitive data exposed in logs
- Location: `src\lib\logger.js` at L10
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
   9 | function logAuthEventSafe(logger, session, password) {
  10 |   logger.info('login_attempt', {
  11 |     userId: session.userId,
```

### src\routes\integrations.js

- Score: 2.5/10
- Findings: 2
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 2 finding(s), led by a critical-impact/high-likelihood Server-side request forgery through untrusted destination (10/10 risk). Primary issue family: Injection & Execution. 1 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Server-side request forgery through untrusted destination | impact critical \| likelihood high \| risk 10/10 | AI 90% |
| Potential incomplete validation in '/fetch-safe' endpoint | impact medium \| likelihood medium \| risk 5/10 | AI 70% |

#### Server-side request forgery through untrusted destination
- Location: `src\routes\integrations.js` at L7-11
- Risk: CRITICAL impact / HIGH likelihood / 10/10
- Why it matters: The '/fetch-unsafe' endpoint directly uses user-supplied input from 'req.query.url' in a fetch request without validating or sanitizing it. This allows attackers to craft malicious URLs that could access internal services or sensitive resources.
- What to change: Constrain outbound requests to approved destinations, normalize and validate URLs before use, and block internal address ranges, metadata endpoints, and attacker-controlled protocols from request execution paths.
- Safe pattern: Validate and sanitize the 'url' parameter using a strict allowlist of permitted domains or patterns. For example, use a function like 'isAllowedOutboundUrl' to enforce outbound URL policies.
- Validate with: Test internal-address and metadata-endpoint payloads and confirm the server rejects them before any outbound request occurs. | Add regression tests for redirects, alternate IP encodings, and unexpected protocols. | Review outbound request helpers to confirm hostname and resolved-IP validation occur in one consistent path.
- Avoid: Checking only for `http` or `https` while allowing arbitrary hosts. | Allow-listing hostnames without validating final resolved IPs or redirects. | Relying on client-side URL restrictions to keep server-side fetches safe.
- Why likely: The 'url' parameter is directly controlled by the user. | No validation or sanitization is applied to the input.
- Threat: An attacker could exploit this to perform SSRF attacks, potentially accessing internal systems, cloud metadata endpoints, or other restricted resources.
- Mappings: OWASP: A10 | ATT&CK: T1190 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: fetch(req.query.url), user-controlled URL
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

#### Potential incomplete validation in '/fetch-safe' endpoint
- Location: `src\routes\integrations.js` at L14-20
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The '/fetch-safe' endpoint uses 'isAllowedOutboundUrl' to validate the 'url' parameter, but the implementation of this function is not provided. If the validation is incomplete or bypassable, the endpoint may still be vulnerable to SSRF.
- What to change: Ensure that 'isAllowedOutboundUrl' implements strict validation, such as checking against a predefined allowlist of domains and rejecting any unexpected or malformed URLs.
- Why likely: The validation function is not shown, so its robustness cannot be confirmed. | The endpoint still relies on user-supplied input for the fetch request.
- Threat: If the validation function is not robust, attackers could bypass it and exploit the endpoint for SSRF attacks.
- Mappings: OWASP: A10 | ATT&CK: T1190 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: isAllowedOutboundUrl(req.query.url), user-controlled URL
- AI grounding: Curated framework pack
- Code involved in the reasoning:
```text
  13 | router.get('/fetch-safe', requireAdmin, async (req, res) => {
  14 |   if (!isAllowedOutboundUrl(req.query.url)) {
  15 |     return res.status(400).json({ error: 'outbound_url_blocked' });
  16 |   }
  17 | 
  18 |   const response = await fetch(req.query.url);
  19 |   const body = await response.text();
  20 |   res.json({ ok: true, body });
  21 | });
```

### src\middleware\csrf.js

- Score: 4.8/10
- Findings: 2
- Frameworks in scope: OWASP 2021, STRIDE 2026.1, CWE 4.15, MITRE 15, NIST Rev. 5, PCIDSS 4.0.1, CLEANCODE 2024-curated
- Summary: 2 finding(s), led by a high-impact/high-likelihood Hardcoded token in source code (9/10 risk). Primary issue family: Secrets & Credential Exposure. 1 additional finding(s) also detected.
- Intelligence source: Bundled Fallback | no verified packs loaded

| Finding | Score Factors | Detection |
| --- | --- | --- |
| Hardcoded token in source code | impact high \| likelihood high \| risk 9/10 | AI 90% |
| Missing CSRF protection on state-changing request | impact medium \| likelihood medium \| risk 5/10 | AI 80% |

#### Hardcoded token in source code
- Location: `src\middleware\csrf.js` at L3-5
- Risk: HIGH impact / HIGH likelihood / 9/10
- Why it matters: The CSRF token is hardcoded as 'known-good-demo-token', which makes it predictable and vulnerable to exploitation. An attacker could easily guess or obtain this token and bypass CSRF protection.
- What to change: Replace hardcoded bearer tokens, session tokens, and integration tokens with managed secret delivery, and revoke or rotate any token that was exposed in source or build artifacts.
- Safe pattern: Generate a unique CSRF token for each user session and validate it server-side. Store the token securely and ensure it is not hardcoded in the source code.
- Validate with: Search the repository, generated bundles, and environment templates to confirm the old token is gone. | Verify integrations still function when the token is loaded from managed configuration. | Confirm the exposed token has been revoked or rotated and cannot be used successfully.
- Avoid: Keeping the token in a checked-in environment file or sample configuration. | Masking part of the token while continuing to ship the usable secret with the application. | Removing the token from source but leaving the compromised token active.
- Why likely: The hardcoded token is easily exploitable as it is static and predictable | making it highly likely to be abused by attackers.
- Threat: An attacker could forge requests on behalf of a user, potentially leading to unauthorized actions such as account changes or data manipulation.
- Mappings: CWE: CWE-798 | OWASP: A05 | NIST: IA-5
- STRIDE: Tampering
- Matched signals: token
- Sources: OWASP Secrets Management Cheat Sheet, CWE-798 Use of Hard-coded Credentials
- AI grounding: Curated framework pack | OWASP Secrets Management Cheat Sheet
- Code involved in the reasoning:
```text
   2 |   const token = req.headers['x-csrf-token'];
   3 |   if (!token || token !== 'known-good-demo-token') {
   4 |     return res.status(403).json({ error: 'csrf_invalid' });
   5 |   }
   6 |   next();
```

#### Missing CSRF protection on state-changing request
- Location: `src\middleware\csrf.js` at L3-5
- Risk: MEDIUM impact / MEDIUM likelihood / 5/10
- Why it matters: The CSRF protection mechanism relies solely on a token in the request header without ensuring that the token is unique per session or user. This design is insecure and can be bypassed.
- What to change: Protect state-changing browser requests with anti-CSRF tokens or equivalent same-site defenses, and ensure sensitive actions cannot be triggered cross-origin by ambient browser credentials alone.
- Safe pattern: Implement a robust CSRF protection mechanism using unique tokens for each user session. Use a secure library to generate and validate these tokens.
- Validate with: Attempt a cross-site form or request trigger and confirm the state-changing action is rejected without a valid token. | Add tests proving mutating routes fail when cookie-authenticated requests omit or forge the anti-CSRF token. | Review same-site, origin-check, and token behavior across all browser-authenticated state-changing flows.
- Avoid: Relying only on referer checks or client-side JavaScript restrictions. | Disabling CSRF middleware because the route is called by fetch or SPA code. | Treating hidden form fields without server validation as CSRF protection.
- Why likely: The current implementation does not provide sufficient protection against CSRF attacks | but the presence of a token check reduces the likelihood of exploitation compared to having no protection at all.
- Threat: An attacker could exploit this weakness to perform unauthorized actions on behalf of a user by guessing or obtaining the static token.
- Mappings: CWE: CWE-352 | OWASP: A04 | NIST: AC-3
- STRIDE: Elevation of Privilege
- Matched signals: csrf
- Sources: OWASP Cross-Site Request Forgery Prevention Cheat Sheet, CWE-352 Cross-Site Request Forgery
- AI grounding: Curated framework pack | OWASP Cross-Site Request Forgery Prevention Cheat Sheet
- Code involved in the reasoning:
```text
   2 |   const token = req.headers['x-csrf-token'];
   3 |   if (!token || token !== 'known-good-demo-token') {
   4 |     return res.status(403).json({ error: 'csrf_invalid' });
   5 |   }
   6 |   next();
```

## Scan Warnings

- src\lib\uploadPolicy.js: AI provider unavailable: Azure Foundry error: 429
- src\lib\urlPolicy.js: AI provider unavailable: Azure Foundry error: 429
- src\middleware\auth.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\auth.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\browser.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\documents.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\logs.js: AI provider unavailable: Azure Foundry error: 429
- src\routes\search.js: AI provider unavailable: Azure Foundry error: 429
- src\server.js: AI provider unavailable: Azure Foundry error: 429
