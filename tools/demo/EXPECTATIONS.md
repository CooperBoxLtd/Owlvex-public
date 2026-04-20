# Demo Fixture Expectations

This file is the source of truth for the single-file fixture corpus in `tools/demo/`.

Purpose:

- define expected scanner outcomes for the current stabilization set
- prevent future changes from relying on memory or anecdotal report review
- separate intentionally unsafe fixtures from safe companion fixtures

These expectations should be read together with:

- [STABILIZATION_CONTRACT.md](../../docs/STABILIZATION_CONTRACT.md)
- [DEMO_RUNBOOK.md](../../docs/DEMO_RUNBOOK.md)

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
| `34-sqli-concat-unsafe.js` | finding expected | SQL built through string concatenation |
| `35-sqli-concat-safe.js` | clean | parameter binding keeps value out of SQL text |
| `36-python-command-injection-unsafe.py` | finding expected | shell execution from request input |
| `37-python-command-injection-safe.py` | clean | argument list with shell disabled |
| `38-python-sqli-unsafe.py` | finding expected | Python SQL f-string reaches execute |
| `39-python-sqli-safe.py` | clean | parameterized Python SQL query |
| `40-python-path-traversal-unsafe.py` | finding expected | request-derived Python file path |
| `41-python-path-traversal-safe.py` | clean | fixed Python file path |
| `42-python-ssrf-unsafe.py` | finding expected | request-derived Python outbound request |
| `43-python-ssrf-safe.py` | clean | fixed outbound Python destination |
| `44-python-jwt-validation-unsafe.py` | finding expected | Python JWT decode skips signature verification |
| `45-python-jwt-validation-safe.py` | clean | Python JWT verification enforces signature checking |
| `46-java-command-injection-unsafe.java` | finding expected | Java Runtime exec from request input |
| `47-java-command-injection-safe.java` | clean | Java ProcessBuilder argument list |
| `48-java-sqli-unsafe.java` | finding expected | Java SQL built through string concatenation |
| `49-java-sqli-safe.java` | clean | Java PreparedStatement parameter binding |
| `50-java-path-traversal-unsafe.java` | finding expected | request-derived Java file path |
| `51-java-path-traversal-safe.java` | clean | fixed Java file path |
| `52-java-ssrf-unsafe.java` | finding expected | request-derived Java outbound request |
| `53-java-ssrf-safe.java` | clean | fixed outbound Java destination |
| `54-java-jwt-validation-unsafe.java` | finding expected | Java JWT decode without verification |
| `55-java-jwt-validation-safe.java` | clean | Java JWT require/verify path |
| `56-java-deserialization-unsafe.java` | finding expected | Java ObjectInputStream on request input |
| `57-java-deserialization-safe.java` | clean | Java JSON parsing of request input |
| `58-csharp-command-injection-unsafe.cs` | finding expected | C# Process.Start from request input |
| `59-csharp-command-injection-safe.cs` | clean | C# Process.Start fixed executable and args |
| `60-csharp-sqli-unsafe.cs` | finding expected | C# SQL built through string concatenation |
| `61-csharp-sqli-safe.cs` | clean | C# SqlCommand parameter binding |
| `62-csharp-path-traversal-unsafe.cs` | finding expected | request-derived C# file path |
| `63-csharp-path-traversal-safe.cs` | clean | fixed C# file path |
| `64-csharp-ssrf-unsafe.cs` | finding expected | request-derived C# outbound request |
| `65-csharp-ssrf-safe.cs` | clean | fixed outbound C# destination |
| `66-go-command-injection-unsafe.go` | finding expected | Go shell execution from request input |
| `67-go-command-injection-safe.go` | clean | Go fixed executable with explicit args |
| `68-go-sqli-unsafe.go` | finding expected | Go SQL built through string concatenation |
| `69-go-sqli-safe.go` | clean | Go parameterized database call |
| `70-go-path-traversal-unsafe.go` | finding expected | request-derived Go file path |
| `71-go-path-traversal-safe.go` | clean | fixed Go file path |
| `72-go-ssrf-unsafe.go` | finding expected | request-derived Go outbound request |
| `73-go-ssrf-safe.go` | clean | fixed outbound Go destination |
| `74-go-jwt-validation-unsafe.go` | finding expected | Go ParseUnverified on request token |
| `75-go-jwt-validation-safe.go` | clean | Go jwt.Parse with key function |

## Stabilization Rule

For the current trusted issue set, every safe companion above must stay clean and every unsafe companion above must remain detectable.

If a future change alters one of these outcomes, that change is not automatically an improvement. It must be explained, benchmarked, and reviewed against the stabilization contract.

## Exploratory AI Fixtures

The files below are intentionally outside the current deterministic stabilization gate. They exist to exercise AI-backed reasoning on patterns we want to improve without pretending they are proof-grade yet.

| File | Intended AI focus | Notes |
| --- | --- | --- |
| `76-nosql-injection-unsafe.js` | finding likely | client-controlled Mongo-style filter object |
| `77-nosql-injection-safe.js` | should stay quiet | explicit allow-listed NoSQL filter |
| `78-mass-assignment-unsafe.js` | finding likely | request body spread into update payload |
| `79-mass-assignment-safe.js` | should stay quiet | explicit profile field allow-list |
| `80-unprotected-admin-route-unsafe.js` | finding likely | admin route without visible guard |
| `81-unprotected-admin-route-safe.js` | should stay quiet | explicit admin middleware present |
| `82-privilege-escalation-unsafe.js` | finding likely | authenticated user can assign account roles |
| `83-privilege-escalation-safe.js` | should stay quiet | admin gate plus role allow-list |
| `84-audit-gap-unsafe.js` | finding likely | privileged suspension action has no audit trail |
| `85-audit-gap-safe.js` | should stay quiet | privileged action records audit event |
| `86-pii-overexposure-unsafe.js` | finding likely | full account object returned to client |
| `87-pii-overexposure-safe.js` | should stay quiet | response projects only safe profile fields |
| `88-approval-workflow-bypass-unsafe.js` | finding likely | auth-only refund approval despite stronger business rule |
| `89-approval-workflow-bypass-safe.js` | should stay quiet | finance-approver gate enforced before approval |

These fixtures are review aids, not release-gated proof claims. If we later promote any of these families into deterministic coverage, they should move into the main expectation table with unsafe/safe benchmark requirements.
