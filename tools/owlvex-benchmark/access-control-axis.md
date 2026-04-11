# Access Control Axis

This document defines the canonical deterministic access-control pipeline inside Owlvex.

It exists to lock down ownership boundaries, data contracts, and invariants for the access-control reasoning axis — the third complete axis in the benchmark tool.

## Threat Model

The primary threat this axis targets is **IDOR (Insecure Direct Object Reference)** — also known as BOLA (Broken Object Level Authorization).

An IDOR occurs when:
1. A caller-supplied identifier (docId, userId, resourceId) is used to access a resource
2. No ownership or authorization policy verifies the caller is permitted to access that specific resource
3. The authentication layer only confirms the caller is logged in, not that they own the resource

## Layer Order

Access-control evaluation must flow in this order:

1. `AC-002` subject classification
2. `AC-004` resource shape
3. `AC-003` policy check
4. `AC-005` context validation
5. `AC-001` final policy decision

Later layers may consume earlier outputs.
Earlier layers must never depend on later layers.

## Ownership

### AC-002

Owns:

- classification of handler parameters as SESSION or UNTRUSTED
- determination of subject source (who is making the request)
- identification of caller-supplied identifiers in function signature

Does not own:

- how those identifiers are used in the query
- what authorization checks are present
- final vulnerability policy decisions

### AC-004

Owns:

- classification of resource access shape (OWNED, ARBITRARY, CONSTANT)
- determination of whether the query scopes to the current user's resources
- identification of session-bound vs caller-supplied query parameters

Does not own:

- subject identity classification
- authorization policy evaluation
- final vulnerability policy decisions

### AC-003

Owns:

- identification of authorization patterns in handler body
- classification of policy check type (EXPLICIT, OWNERSHIP, ROLE, AUTH_ONLY, MISSING)
- determination of whether a meaningful authorization check exists

Does not own:

- subject classification
- resource access patterns
- SQL query semantics
- final vulnerability policy decisions

### AC-005

Owns:

- context validation: given the resource shape (AC-004) and policy check (AC-003), is the combination safe?
- effective risk determination for the access pattern
- invalidation when ARBITRARY resource has insufficient policy

Does not own:

- subject propagation
- query structure
- authorization pattern detection
- final vulnerability policy decisions outside context validation

### AC-001

Owns:

- final access-control decision
- policy consumption of subject, resource, policy, and context outputs

Does not own:

- subject inference
- resource shape inference
- authorization pattern detection
- context inference

## Data Contracts

### AC-002 output

Must provide:

- `params`: array of `{ param, classification }` where classification is `SESSION | UNTRUSTED | UNKNOWN`
- `subjectSource`: `SESSION | UNTRUSTED | MIXED | UNKNOWN`
- `finding`: boolean — true if any UNTRUSTED identifier parameter is present

### AC-004 output

Must provide:

- `sink`: query method name, or null if no query found
- `queryArgs`: raw argument text, or null
- `resourceShape`: `OWNED | ARBITRARY | CONSTANT | UNKNOWN`
- `finding`: boolean — true if resourceShape is ARBITRARY

### AC-003 output

Must provide:

- `policyCheck`: `EXPLICIT | OWNERSHIP | ROLE | AUTH_ONLY | MISSING`
- `finding`: boolean — true if policyCheck is MISSING or AUTH_ONLY

### AC-005 output

Must provide:

- `resourceShape`: from AC-004
- `policyCheck`: from AC-003
- `contextValid`: boolean
- `effectiveRisk`: `IDOR | NONE`
- `finding`: boolean — true if effectiveRisk is IDOR

### AC-001 input contract

AC-001 must consume:

- subject source from AC-002
- resource shape from AC-004
- policy check from AC-003
- context validity from AC-005

AC-001 must not reconstruct any of those from raw source strings.

## Invariants

### Subject ownership

- AC-001 must never infer subject source
- subject classification lives entirely in AC-002
- MIXED subject source (both SESSION and UNTRUSTED params) is treated as having UNTRUSTED identifiers present

### Resource ownership

- resource shape is owned by AC-004
- OWNED means the WHERE clause is scoped to the authenticated user's ID
- ARBITRARY means a caller-supplied variable reaches the WHERE clause without session binding
- CONSTANT means only string/numeric literals are used

### Policy ownership

- authorization pattern detection lives entirely in AC-003
- policy priority order: EXPLICIT > OWNERSHIP > ROLE > AUTH_ONLY > MISSING
- AUTH_ONLY is always insufficient for ARBITRARY resources

### Context rules

- OWNED or CONSTANT resources are contextually safe regardless of policy check
- ARBITRARY + (EXPLICIT | OWNERSHIP | ROLE) → contextValid = true
- ARBITRARY + (MISSING | AUTH_ONLY) → contextValid = false → IDOR

### Policy rules

- AC-001 is a thin consumer
- final access-control finding is a deterministic consequence of:
  - resource shape
  - policy check
  - context validity

## Forbidden Behavior

The following are explicitly forbidden:

- reconstructing resource shape from source-code strings in AC-001
- inferring authorization patterns outside AC-003
- allowing AC-004 to make policy decisions
- allowing AC-003 to modify resource shape
- mixing benchmark expectations across layers without updating corpus assertions

## Release Gate

The access-control axis is considered healthy only when all of these pass:

- `npm run benchmark:ac002`
- `npm run benchmark:ac004`
- `npm run benchmark:ac003`
- `npm run benchmark:ac005`
- `npm run benchmark:ac001`
- `npm run benchmark:ac-integration`

The preferred aggregate gate is:

```bash
npm run benchmark:deterministic
```

## v1 Complete Criteria

Access-control v1 is complete when:

- all five deterministic rule layers exist
- all five suites pass
- integration coverage exists and passes
- the aggregate deterministic runner passes
- the contract in this document remains true
- future changes preserve ownership boundaries

## Bottom Line

This axis enforces the principle that authentication and authorization are different concerns.

The key rule is simple:

Being logged in does not mean you are authorized to access any specific resource. AC-001 finds the gap.
