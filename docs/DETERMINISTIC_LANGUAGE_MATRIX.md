# Deterministic Language Matrix

## Purpose

This matrix is the product-facing source of truth for what Owlvex currently proves deterministically by language and family.

It exists to keep three things aligned:

- engine scope
- benchmark scope
- product language

If a cell is marked as supported here, there should be:

- a bounded deterministic rule
- at least one unsafe fixture
- at least one safe companion
- a benchmark expectation that protects the claim

## Current Matrix

| Family | JavaScript / TypeScript | Python | Java | C# | Notes |
| --- | --- | --- | --- | --- | --- |
| Command injection | Yes | Yes | Yes | Yes | Python covers `os.system(...)` and `subprocess.*(..., shell=True)`; Java covers `Runtime.getRuntime().exec(...)`; C# covers `Process.Start(...)` on request-derived command strings |
| SQL injection | Yes | Yes | Yes | Yes | Python covers f-string SQL; Java covers concatenated SQL reaching `Statement.execute*`; C# covers concatenated SQL reaching `SqlCommand` |
| Path traversal | Yes | Yes | Yes | Yes | Python covers `os.path.join(...)`; Java covers `Paths.get(...)` / `Path.of(...)`; C# covers `Path.Combine(...)` into file-reading sinks |
| SSRF | Yes | Yes | Yes | Yes | Python covers direct `requests.*(...)`; Java covers `new URL(requestInput).openStream()`; C# covers `HttpClient.GetStringAsync(...)` on request-derived destinations |
| Weak JWT validation | Yes | Yes | Yes | No | Python covers `jwt.decode(..., options={"verify_signature": False})`; Java covers `JWT.decode(...)` on request-derived tokens |
| Insecure deserialization | No | Yes | Yes | No | Python covers `pickle.loads(request.body)`; Java covers `ObjectInputStream` on request input |
| IDOR / tenant isolation | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| Open redirect | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| CSRF | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| CORS | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| Cookie security | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| Sensitive logging | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |
| Debug mode | Yes | No | No | No | Python, Java, and C# not yet implemented deterministically |

## Benchmark Rule

When a new deterministic language cell is added:

1. add the rule
2. add unsafe and safe fixtures
3. add detection, posture, and clean expectations
4. add suppression coverage if the AI lane can still overclaim on the safe companion

Do not mark a language/family cell as supported until all four are in place.

## Current Next Targets

Recommended next deterministic language expansions:

1. Python auth/session safe guards and framework-aware variants
2. Java framework-aware safe guards and auth/session variants
3. C# auth/session and framework-aware safe guards

## Positioning Rule

Owlvex analyzes many languages, but deterministic proof is only claimed where a bounded rule contract and benchmark-backed support matrix cell exist.
