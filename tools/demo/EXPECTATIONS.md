# Demo Fixture Expectations

This file is the source of truth for the single-file fixture corpus in `tools/demo/`.

Purpose:

- define expected scanner outcomes for the current stabilization set
- prevent future changes from relying on memory or anecdotal report review
- separate intentionally unsafe fixtures from safe companion fixtures

These expectations should be read together with:

- [STABILIZATION_CONTRACT.md](../../docs/STABILIZATION_CONTRACT.md)
- [DEMO-SCRIPT.md](./DEMO-SCRIPT.md)

## Expected Outcomes

| File | Expectation | Notes |
| --- | --- | --- |
| `01-idor-unsafe.js` | finding expected | IDOR / broken access control |
| `02-idor-safe.js` | clean | ownership check present |
| `03-debug-unsafe.js` | finding expected | debug active without production guard |
| `04-debug-safe.js` | clean | debug activation guarded |
| `05-tenant-isolation-unsafe.js` | finding expected | tenant scoping missing |
| `06-sqli-unsafe.js` | finding expected | unsanitized SQL construction |
| `07-sqli-safe.js` | clean | parameterized query |
| `08-command-injection-unsafe.js` | finding expected | unsafe shell execution |
| `09-command-injection-safe.js` | clean | safe argument handling |
| `10-cookie-unsafe.js` | finding expected | insecure cookie flags |
| `11-cookie-safe.js` | clean | secure cookie flags present |
| `12-sensitive-logging-unsafe.js` | finding expected | raw secret logging |
| `13-sensitive-logging-safe.js` | clean | redacted / safe logging pattern |
| `14-sqli-context-mismatch-unsafe.js` | finding expected | real SQL risk despite context noise |
| `15-sqli-context-mismatch-safe.js` | clean | safe companion for context mismatch |
| `16-open-redirect-unsafe.js` | finding expected | open redirect |
| `17-open-redirect-safe.js` | clean | redirect allowlist / safe resolver |
| `18-csrf-unsafe.js` | finding expected | missing CSRF protection |
| `19-csrf-safe.js` | clean | CSRF protection present |
| `20-cors-unsafe.js` | finding expected | permissive CORS |
| `21-cors-safe.js` | clean | narrow CORS policy |
| `22-ssrf-unsafe.js` | finding expected | outbound fetch from user input |
| `23-ssrf-safe.js` | clean | allowlisted outbound fetch |
| `24-jwt-validation-unsafe.js` | finding expected | weak JWT validation |
| `25-jwt-validation-safe.js` | clean | expected validation path |
| `26-deserialization-unsafe.py` | finding expected | executable deserializer present |
| `27-deserialization-safe.py` | clean | data-only JSON parsing |
| `28-path-traversal-unsafe.js` | finding expected | request-derived filesystem path |
| `29-path-traversal-safe.js` | clean | identifier map before file access |
| `30-ssrf-allowlist-unsafe.js` | finding expected | weak substring host validation |
| `31-ssrf-allowlist-safe.js` | clean | exact trusted host allow-list |
| `32-command-injection-shell-unsafe.js` | finding expected | shell:true with interpolated command |
| `33-command-injection-shell-safe.js` | clean | argument array without shell parsing |

## Stabilization Rule

For the current trusted issue set, every safe companion above must stay clean and every unsafe companion above must remain detectable.

If a future change alters one of these outcomes, that change is not automatically an improvement. It must be explained, benchmarked, and reviewed against the stabilization contract.
