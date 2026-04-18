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

| Family | JavaScript / TypeScript | Python | Notes |
| --- | --- | --- | --- |
| Command injection | Yes | Yes | Python covers `os.system(...)` and `subprocess.*(..., shell=True)` with request-derived or interpolated commands |
| SQL injection | Yes | Yes | Python covers f-string SQL reaching `execute/query` sinks |
| Path traversal | Yes | Yes | Python covers `os.path.join(...)` with request-derived input flowing into file sinks |
| SSRF | Yes | Yes | Python covers direct `requests.*(...)` on request-derived destinations |
| Weak JWT validation | Yes | Yes | Python covers `jwt.decode(..., options={"verify_signature": False})` |
| Insecure deserialization | No | Yes | Python currently covers `pickle.loads(request.body)` |
| IDOR / tenant isolation | Yes | No | Python not yet implemented deterministically |
| Open redirect | Yes | No | Python not yet implemented deterministically |
| CSRF | Yes | No | Python not yet implemented deterministically |
| CORS | Yes | No | Python not yet implemented deterministically |
| Cookie security | Yes | No | Python not yet implemented deterministically |
| Sensitive logging | Yes | No | Python not yet implemented deterministically |
| Debug mode | Yes | No | Python not yet implemented deterministically |

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
2. Java wave 1 for:
   - command injection
   - SQL injection
   - path traversal
   - SSRF
   - deserialization
3. C# after Java using the same bounded family set

## Positioning Rule

Owlvex analyzes many languages, but deterministic proof is only claimed where a bounded rule contract and benchmark-backed support matrix cell exist.
