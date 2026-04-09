# Owlvex Issue Expansion Roadmap

## Purpose

Owlvex now has a stronger reasoning engine than issue library.

That means the next scaling problem is not only `how well Owlvex reasons`, but also `what Owlvex can reason about`.

This roadmap defines the next expansion of the canonical issue catalog so the product can move from a strong v1 core set toward broader production-grade AppSec coverage.

## Current State

The live catalog currently contains:

- `33` canonical issue definitions
- `9` issue families

That is enough for:

- a strong prototype
- meaningful reporting and comparison
- corpus-based benchmarking
- early product demos

It is not yet enough for broad production security coverage across:

- backend APIs
- frontend/browser risks
- auth/session variants
- secrets and key handling variants
- platform misconfiguration
- resilience and abuse cases

## Expansion Goals

Owlvex v2 should aim for:

- `100+` canonical issues
- clear family and subfamily structure
- stronger primary and secondary framework mappings
- richer remediation summaries and exploit narratives
- negative signals and discriminators for every new cluster
- corpus coverage for every major family expansion

## Family Targets

Recommended issue count targets by family:

| Family | Current | Target | Priority |
| --- | ---: | ---: | --- |
| Injection & Execution | 12 | 20 | Highest |
| Identity & Auth Failures | 3 | 12 | Highest |
| Access Control & Authorization | 5 | 12 | Highest |
| Secrets & Credential Exposure | 4 | 12 | Highest |
| Data Protection & Privacy | 2 | 12 | High |
| Security Misconfiguration & Platform Hardening | 3 | 12 | High |
| Audit & Observability | 1 | 8 | Medium |
| Availability & Resilience | 1 | 8 | Medium |
| Cryptography & Randomness | 2 | 8 | Medium |

This gives a practical v2 range of `104` issues without turning the ontology into an unmanageable dump.

## Expansion Principles

1. Expand by family, not by random issue list
2. Add negative signals and corpus cases together with each issue cluster
3. Prefer developer-recognizable issues before niche compliance-only variants
4. Keep canonical issues specific enough to be useful, but not so narrow that they become impossible to benchmark
5. Treat framework mappings as support, not as the primary identity

## First 25 Issues To Add

### Injection & Execution

1. `owlvex.issue.sql_injection.blind.001`
2. `owlvex.issue.orm_query_builder_bypass.001`
3. `owlvex.issue.shell_argument_injection.001`
4. `owlvex.issue.code_injection.eval.001`
5. `owlvex.issue.xpath_injection.001`
6. `owlvex.issue.smtp_header_injection.001`

### Identity & Auth Failures

7. `owlvex.issue.session_fixation.001`
8. `owlvex.issue.missing_mfa_enforcement.001`
9. `owlvex.issue.insecure_password_reset.001`
10. `owlvex.issue.auth_bypass_trust_header.001`
11. `owlvex.issue.missing_account_lockout.001`

### Access Control & Authorization

12. `owlvex.issue.broken_function_level_authorization.001`
13. `owlvex.issue.broken_object_level_authorization.002`
14. `owlvex.issue.tenant_boundary_bypass.001`
15. `owlvex.issue.mass_data_exposure_scope_bypass.001`
16. `owlvex.issue.unsafe_file_download_authorization.001`

### Secrets & Credential Exposure

17. `owlvex.issue.private_key_in_source.001`
18. `owlvex.issue.cloud_access_key_exposure.001`
19. `owlvex.issue.jwt_signing_secret_exposure.001`
20. `owlvex.issue.secret_in_client_bundle.001`

### Data Protection & Privacy

21. `owlvex.issue.pii_logging.001`
22. `owlvex.issue.stack_trace_exposure.001`
23. `owlvex.issue.unencrypted_sensitive_transport.001`

### Security Misconfiguration & Platform Hardening

24. `owlvex.issue.debug_mode_enabled.001`
25. `owlvex.issue.default_credentials_enabled.001`

## Recommended Build Order

### Wave 1

Focus on the highest-value product coverage:

- Injection & Execution
- Identity & Auth Failures
- Access Control & Authorization
- Secrets & Credential Exposure

Target outcome:

- grow from `33` issues to roughly `55`
- keep corpus and resolver quality stable
- improve practical coverage for demos and early customer repos

### Wave 2

Strengthen report credibility and enterprise usefulness:

- Data Protection & Privacy
- Security Misconfiguration & Platform Hardening
- Audit & Observability

Target outcome:

- grow to roughly `80`
- improve security-report depth
- strengthen operational and compliance-adjacent reporting

### Wave 3

Fill strategic but slightly less common gaps:

- Availability & Resilience
- Cryptography & Randomness
- niche execution/parser families

Target outcome:

- reach `100+`
- improve edge-case and platform coverage

## What Each New Issue Must Include

Every new canonical issue should ship with:

- stable Owlvex issue ID
- family assignment
- severity
- STRIDE categories
- CWE mapping
- OWASP mapping where appropriate
- remediation summary
- cheat sheet references where available
- positive keywords
- negative keywords
- minimum score
- at least one positive corpus case
- at least one negative corpus case

## What Not To Do

Avoid:

- adding issues without corpus coverage
- mapping one issue to too many unrelated frameworks
- adding duplicate issues that differ only by wording
- expanding the catalog faster than the resolver and corpus can support

## Success Criteria

The catalog expansion is working if:

- issue count grows without corpus quality collapsing
- new issues produce clearer reports instead of noisier ones
- families remain understandable to users
- framework mappings stay consistent and defensible
- the corpus remains the source of truth for quality changes

## Recommended Next Step

Start with `Wave 1` and add one issue cluster at a time:

1. define the issue entries
2. add mappings and remediation
3. add corpus cases
4. run benchmark
5. tune discriminators only where needed

That keeps Owlvex growing like a product, not just like a rule dump.
