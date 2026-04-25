# Deterministic Language Matrix

## Purpose

This matrix is the product-facing source of truth for what Owlvex currently proves deterministically by language and family.

The machine-readable companion for this matrix is:

- [issueContracts.ts](/d:/Dev/repos/CodeScanner/extension/src/frameworks/issueContracts.ts:1)

That file is where Owlvex now records:

- canonical issue family proof contracts
- deterministic language claims
- explicit not-claimed boundaries
- safe-pattern expectations per family

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

| Family | JavaScript / TypeScript | Python | Java | C# | Go | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Command injection | Yes | Yes | Yes | Yes | Yes | Python covers `os.system(...)` and `subprocess.*(..., shell=True)`; Java covers `Runtime.getRuntime().exec(...)`; C# covers `Process.Start(...)`; Go covers `exec.Command("sh", "-c", ...)` on request-derived command strings |
| SQL injection | Yes | Yes | Yes | Yes | Yes | Python covers f-string SQL; Java covers concatenated SQL reaching `Statement.execute*`; C# covers concatenated SQL reaching `SqlCommand`; Go covers concatenated SQL reaching `db.Query/Exec/QueryRow` |
| Path traversal | Yes | Yes | Yes | Yes | Yes | All five language cells now emit Engine 1.0 evidence contracts in the regression gate: request source, path construction flow, filesystem sink, missing base-directory guard, and safe companion suppression. Python covers `os.path.join(...)`; Java covers `Paths.get(...)` / `Path.of(...)`; C# covers `Path.Combine(...)`; Go covers `filepath.Join(...)` into file-reading or file-serving sinks |
| SSRF | Yes | Yes | Yes | Yes | Yes | Python covers direct `requests.*(...)`; Java covers `new URL(requestInput).openStream()`; C# covers `HttpClient.GetStringAsync(...)`; Go covers `http.Get(...)` / `client.Get(...)` on request-derived destinations |
| Weak JWT validation | Yes | Yes | Yes | No | Yes | Python covers `jwt.decode(..., options={"verify_signature": False})`; Java covers `JWT.decode(...)`; Go covers `ParseUnverified(...)` on request-derived tokens |
| Insecure deserialization | No | Yes | Yes | No | No | Python covers `pickle.loads(request.body)`; Java covers `ObjectInputStream` on request input |
| IDOR / tenant isolation | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| Open redirect | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| CSRF | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| CORS | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| Cookie security | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| Sensitive logging | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |
| Debug mode | Yes | No | No | No | No | Python, Java, C#, and Go not yet implemented deterministically |

## Benchmark Rule

When a new deterministic language cell is added:

1. add the rule
2. add unsafe and safe fixtures
3. add detection, posture, and clean expectations
4. add suppression coverage if the AI lane can still overclaim on the safe companion
5. add an Engine evidence regression case proving source, sink, flow, guard, and verdict for the unsafe fixture

Do not mark a language/family cell as supported until all five are in place.

## Contract Rule

Every supported matrix cell should also line up with an explicit issue proof contract covering:

- proof boundary
- supported deterministic languages
- not-claimed deterministic languages
- safe patterns that must suppress the claim

If a matrix cell and an issue proof contract disagree, the contract should be treated as stale and corrected in the same batch.

## Current Next Targets

Recommended next deterministic language expansions:

1. Go auth/session safe guards and framework-aware variants
2. Python auth/session safe guards and framework-aware variants
3. Java and C# auth/session safe guards

## Positioning Rule

Owlvex analyzes many languages, but deterministic proof is only claimed where a bounded rule contract and benchmark-backed support matrix cell exist.
