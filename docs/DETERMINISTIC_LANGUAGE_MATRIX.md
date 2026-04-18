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

| Family | JavaScript / TypeScript | Python | Java | Notes |
| --- | --- | --- | --- | --- |
| Command injection | Yes | Yes | Yes | Python covers `os.system(...)` and `subprocess.*(..., shell=True)`; Java covers `Runtime.getRuntime().exec(...)` on request-derived command strings |
| SQL injection | Yes | Yes | Yes | Python covers f-string SQL reaching `execute/query` sinks; Java covers concatenated SQL reaching `Statement.execute*` |
| Path traversal | Yes | Yes | Yes | Python covers `os.path.join(...)`; Java covers `Paths.get(...)` / `Path.of(...)` into file-reading sinks |
| SSRF | Yes | Yes | Yes | Python covers direct `requests.*(...)`; Java covers `new URL(requestInput).openStream()` and equivalent URL variables |
| Weak JWT validation | Yes | Yes | No | Python covers `jwt.decode(..., options={"verify_signature": False})` |
| Insecure deserialization | No | Yes | No | Python currently covers `pickle.loads(request.body)` |
| IDOR / tenant isolation | Yes | No | No | Python and Java not yet implemented deterministically |
| Open redirect | Yes | No | No | Python and Java not yet implemented deterministically |
| CSRF | Yes | No | No | Python and Java not yet implemented deterministically |
| CORS | Yes | No | No | Python and Java not yet implemented deterministically |
| Cookie security | Yes | No | No | Python and Java not yet implemented deterministically |
| Sensitive logging | Yes | No | No | Python and Java not yet implemented deterministically |
| Debug mode | Yes | No | No | Python and Java not yet implemented deterministically |

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
2. Java wave 2 for:
   - weak JWT validation
   - insecure deserialization
   - framework-aware safe guards
3. C# after Java using the same bounded family set

## Positioning Rule

Owlvex analyzes many languages, but deterministic proof is only claimed where a bounded rule contract and benchmark-backed support matrix cell exist.
