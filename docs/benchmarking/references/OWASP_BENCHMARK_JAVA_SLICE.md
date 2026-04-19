# OWASP Benchmark Java Slice Starter

## Purpose

This document is the starter mapping for using OWASP Benchmark Java as the first external proof anchor for Owlvex.

It is intentionally narrow.

Owlvex should not claim blanket OWASP Benchmark coverage.
It should only claim mapped slice coverage where:

- the issue family is already supported honestly
- the deterministic contract is bounded
- the benchmark category is close enough to Owlvex's product truth

## Why Java First

OWASP Benchmark is strongest and most established in Java.

That makes it the best first external anchor for:

- deterministic proof credibility
- customer-facing benchmark discussion
- slice-based comparison without overclaiming

## Official OWASP Benchmark Java Areas

The OWASP Benchmark Java project documents these vulnerability areas for Java v1.2:

- Command Injection
- Weak Cryptography
- Weak Hashing
- LDAP Injection
- Path Traversal
- Secure Cookie Flag
- SQL Injection
- Trust Boundary Violation
- Weak Randomness
- XPATH Injection
- XSS (Cross-Site Scripting)

Source:

- OWASP Benchmark project page

## First Included Slice For Owlvex

The first Owlvex-aligned Java slice should include:

| OWASP Benchmark Java area | Include? | Owlvex mapping | Why |
| --- | --- | --- | --- |
| Command Injection | yes | `owlvex.issue.command_injection.001` | already supported deterministically in Java |
| Path Traversal | yes | `owlvex.issue.path_traversal.001` | already supported deterministically in Java |
| SQL Injection | yes | `owlvex.issue.sql_injection.001` | already supported deterministically in Java |
| Secure Cookie Flag | later | `owlvex.issue.insecure_cookie.001` | current deterministic strength is stronger in JS than Java |
| Trust Boundary Violation | later/partial | `owlvex.issue.ssrf.001` and adjacent trust issues | useful conceptually, but mapping must stay narrow |

## Exact Owlvex Rule Mapping For The First Slice

The first slice should map included OWASP Benchmark Java areas to the current deterministic Java rules in Owlvex:

| OWASP Benchmark Java area | Owlvex canonical issue | Owlvex deterministic rule code | Current Owlvex position |
| --- | --- | --- | --- |
| Command Injection | `owlvex.issue.command_injection.001` | `GR-001` | in scope now |
| Path Traversal | `owlvex.issue.path_traversal.001` | `PT-001` | in scope now |

Concrete fixture inventory for this mapping:

- [OWASP_BENCHMARK_JAVA_CASE_INVENTORY.md](D:/Dev/repos/CodeScanner/docs/benchmarking/references/OWASP_BENCHMARK_JAVA_CASE_INVENTORY.md)
- [owasp-benchmark-java-slice.manifest.json](D:/Dev/repos/CodeScanner/docs/benchmarking/references/owasp-benchmark-java-slice.manifest.json)
| SQL Injection | `owlvex.issue.sql_injection.001` | `SQ-001` | in scope now |

Adjacent Java deterministic families that are real in Owlvex but not part of the first OWASP Java external slice:

| Owlvex canonical issue | Owlvex deterministic rule code | Why not in the first OWASP Java slice |
| --- | --- | --- |
| `owlvex.issue.ssrf.001` | `SR-001` | maps only partially to OWASP's broader trust-boundary area and needs a narrower external discussion |
| `owlvex.issue.weak_jwt_validation.001` | `JW-001` | useful in product, but not a clean first-slice OWASP Benchmark Java equivalence |
| `owlvex.issue.insecure_deserialization.001` | `DS-001` | useful in product, but should be discussed separately from the first narrow Java slice |

## Explicitly Excluded From The First Slice

The first slice should exclude:

| OWASP Benchmark Java area | Exclude? | Why |
| --- | --- | --- |
| Weak Cryptography | yes | not the current Java deterministic center of gravity |
| Weak Hashing | yes | not yet benchmark-backed in the current trusted Java surface |
| LDAP Injection | yes | not yet part of the current promoted Java proof surface |
| Weak Randomness | yes | not yet part of the current promoted Java proof surface |
| XPATH Injection | yes | not yet part of the current promoted Java proof surface |
| XSS (Cross-Site Scripting) | yes | not part of the current deterministic Java claim |

## Narrow Mapping Rule

The OWASP Benchmark Java slice should be discussed as:

- an external anchor for selected deterministic families

It should not be discussed as:

- full OWASP Benchmark support
- full Java-language support
- proof that Owlvex covers every major Java vulnerability family

## Initial Owlvex Mapping Candidates

| Owlvex issue family | Owlvex canonical issue | External anchor role | Notes |
| --- | --- | --- | --- |
| SQL injection | `owlvex.issue.sql_injection.001` | direct | strongest fit |
| Command injection | `owlvex.issue.command_injection.001` | direct | good structural fit |
| Path traversal | `owlvex.issue.path_traversal.001` | direct | good structural fit |
| SSRF | `owlvex.issue.ssrf.001` | partial | useful where request-derived outbound destinations are visible |
| Weak JWT validation | `owlvex.issue.weak_jwt_validation.001` | partial | may need Owlvex-native complement rather than direct OWASP Benchmark equivalence |
| Insecure deserialization | `owlvex.issue.insecure_deserialization.001` | direct/partial | useful where executable object-input patterns are explicit |

## Out Of Scope For The First Slice

Do not include in the first OWASP Benchmark Java slice:

- broad AI-only issues
- workflow/business-logic families
- issue classes that require repo-level semantic reasoning
- issue families where Owlvex only has advisory-quality support

## Success Criteria For This Slice

Owlvex can use this slice publicly only when:

1. mapped categories are explicit
2. Owlvex issue-family mapping is written down
3. unsupported categories are visibly excluded
4. benchmark results are stored as artifacts, not anecdotes

## Result Storage Expectation

This slice should eventually produce:

- a benchmark scorecard artifact
- included-category counts
- excluded-category list
- result notes explaining partial mappings and deliberate omissions

See:

- [OWASP_BENCHMARK_JAVA_SCORECARD_TEMPLATE.md](D:/Dev/repos/CodeScanner/docs/benchmarking/references/OWASP_BENCHMARK_JAVA_SCORECARD_TEMPLATE.md)

## Next Population Work

The next step after this starter doc is:

- map included areas to specific deterministic rule codes and product language
- define how results will be stored and compared
- record exact excluded categories and why in a future scorecard
