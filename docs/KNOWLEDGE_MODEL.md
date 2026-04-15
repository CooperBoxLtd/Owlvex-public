# Owlvex Knowledge Model

## Purpose

Owlvex should not treat OWASP, CWE, STRIDE, ATT&CK, CAPEC, and NIST as separate scanners.

Owlvex should also not present those frameworks as if they are interchangeable detection engines.
They are external taxonomies, threat-models, or control lenses that attach to an Owlvex-native issue model.

It should treat them as inputs to a single canonical issue model.

That model gives Owlvex:

- one internal language for findings
- one place to attach multiple framework mappings
- one structure for scan results, reports, and correlation
- one durable format for future dataset imports

## Design Principles

1. `issue` is the core object, not `framework`
2. external frameworks map into canonical Owlvex issues
3. `CWE` is the primary weakness backbone
4. `STRIDE` is an Owlvex-native curated reasoning layer
5. `OWASP` provides risk framing and developer familiarity
6. `CAPEC` and `ATT&CK` provide attacker-path context
7. `NIST` and other control sets provide compliance mappings

This means the decision boundary stays Owlvex-native:

- Owlvex determines whether a finding exists
- frameworks help classify, explain, map, and report that finding
- changing selected frameworks should change interpretation scope more readily than detection truth

For the AI lane, framework scope can be used more directly as reasoning guidance:

- selected frameworks may influence which uncovered issue classes are emphasized
- selected frameworks may influence remediation style, vocabulary, and correlation detail
- AI output should still resolve back into Owlvex canonical issues where possible
- AI framework guidance must not be mistaken for deterministic proof

## Canonical Objects

Owlvex should standardize on three core artifacts:

1. `Owlvex Issue`
   A normalized finding definition used by scans, reports, and AI reasoning.

2. `Framework Catalog Entry`
   A versioned description of a framework or curated profile available in Owlvex.

3. `Framework Mapping`
   A structured bridge between a canonical issue and external frameworks.

## Recommended Ownership

- `docs/schemas/issue.schema.v1.json`
  Canonical issue schema

- `docs/schemas/framework-catalog.schema.v1.json`
  Curated framework metadata schema

- `docs/schemas/issue-mapping.schema.v1.json`
  Mapping and correlation schema

- `docs/schemas/provenance.schema.v1.json`
  Trusted-source provenance schema for curated grounded data

## First Curated Pack

The first concrete Owlvex rule pack now exists in:

- `docs/data/stride/owlvex.stride.2026.1.json`
  Versioned STRIDE reasoning profile

- `docs/data/issues/owlvex-issue-pack.v1.json`
  Expanded canonical Owlvex issue pack

- `docs/data/issues/owlvex-issue-mappings.v1.json`
  Cross-framework mappings for the canonical issue pack

- `docs/data/frameworks/owlvex.framework-pack.2026.1.json`
  Curated framework blob pack with prompt-oriented guidance, upstream provenance, and source blob references

- `docs/data/cheatsheets/owlvex.owasp-cheatsheets.2026.1.json`
  Curated OWASP Cheat Sheet Series pack linked to Owlvex issues and remediation entries

This gives Owlvex a practical starting point for:

- versioned STRIDE reasoning
- CWE-backed issue identity
- OWASP and API OWASP risk framing
- CAPEC and ATT&CK attacker context
- NIST control mappings

The next planned growth step is documented in:

- `docs/ISSUE_EXPANSION_ROADMAP.md`
  v2 catalog expansion targets, priorities, and first-wave issue clusters

## Family-Aware Golden Corpus

Owlvex also includes a family-aware golden corpus in:

- `corpus/README.md`
- `corpus/manifest.json`

This corpus exists to benchmark the canonical knowledge layer, not just raw model output.

Each case declares:

- the source file
- the expected canonical issue IDs
- the expected issue family

That lets Owlvex measure quality at two levels:

1. `Issue-level`
   Whether the resolver found the exact expected canonical issue.
2. `Family-level`
   Whether Owlvex still landed in the correct risk domain even if the issue subtype differed.

This is important because Owlvex’s moat is not only detecting flaws. It is normalizing them into a stable internal security language.

## Canonical Issue Example

```json
{
  "schema_version": "owlvex.issue.v1",
  "id": "owlvex.issue.sql_injection.001",
  "slug": "sql-injection-unsanitized-query-construction",
  "title": "Unsanitized SQL query construction",
  "summary": "User-controlled input is concatenated into a database query.",
  "description": "Application code constructs SQL statements using untrusted input without parameterization, enabling injection of arbitrary SQL fragments.",
  "category": "injection",
  "severity": "high",
  "likelihood": "high",
  "impact": "high",
  "confidence": 0.92,
  "stride": [
    "Tampering",
    "Information Disclosure"
  ],
  "mappings": {
    "cwe": ["CWE-89"],
    "owasp": ["A03:2021"],
    "api_owasp": ["API8:2023"],
    "attack": ["T1190"],
    "capec": ["CAPEC-66"],
    "nist": ["SI-10", "SA-11"]
  },
  "detection": {
    "patterns": [
      "string interpolation into SQL sink",
      "query builder bypass",
      "unparameterized db.query/db.execute"
    ],
    "languages": ["javascript", "typescript", "python", "java", "csharp", "php", "go"],
    "sources": ["request body", "query params", "path params", "headers"],
    "sinks": ["db.query", "db.execute", "cursor.execute"],
    "llm_prompt_hint": "Look for SQL or ORM query strings composed with user input without parameter binding.",
    "confidence_rules": [
      "increase confidence when untrusted input reaches a known SQL sink",
      "reduce confidence when parameterization is visible"
    ]
  },
  "remediation": {
    "summary": "Use parameterized queries or safe ORM bindings.",
    "cheat_sheet_refs": [
      "owasp.cheatsheets.sql_injection_prevention"
    ],
    "code_examples": [
      {
        "language": "javascript",
        "pattern": "db.query('SELECT * FROM users WHERE id = $1', [userId])"
      }
    ]
  },
  "provenance": {
    "source_type": "hybrid",
    "curation_method": "manual",
    "review_status": "reviewed",
    "reviewed_by": "security-team",
    "reviewed_at": "2026-04-14T00:00:00Z",
    "last_verified_at": "2026-04-14T00:00:00Z",
    "sources": [
      {
        "label": "OWASP SQL Injection Prevention Cheat Sheet",
        "kind": "cheat-sheet",
        "publisher": "OWASP"
      },
      {
        "label": "CWE-89",
        "kind": "taxonomy",
        "publisher": "MITRE",
        "document_id": "CWE-89"
      }
    ]
  },
  "evidence_requirements": {
    "must_identify_source": true,
    "must_identify_sink": true,
    "must_include_code_snippet": true
  },
  "tags": ["database", "injection", "input-validation"]
}
```

## STRIDE Formalization

`STRIDE` should be treated as an Owlvex-curated, versioned reasoning profile:

- `owlvex.stride.2026.1`

Recommended STRIDE categories for code scanning:

| Category | Meaning in Owlvex |
| --- | --- |
| `Spoofing` | identity, token, or trust-boundary impersonation flaws |
| `Tampering` | unauthorized data or state modification |
| `Repudiation` | missing auditability, weak accountability, unverifiable actions |
| `Information Disclosure` | secrets leakage, sensitive data exposure, excessive error detail |
| `Denial of Service` | resource exhaustion, abuse amplification, unbounded workloads |
| `Elevation of Privilege` | access-control bypass, privilege escalation, unsafe trust assumptions |

Recommended next step:

- version STRIDE mappings separately from issue schemas
- maintain a curated Owlvex STRIDE profile in source control
- expose STRIDE like any other selectable framework in the extension

## Recommended Build Order

1. adopt the schemas in `docs/schemas/`
2. formalize `owlvex.stride.2026.1`
3. create first canonical issue pack for top security findings
4. map those issues to `CWE -> OWASP -> STRIDE`
5. add `CAPEC`, `ATT&CK`, and `NIST` as richer correlation layers

## Source Guidance

Recommended upstream sources:

- OWASP Top 10
- OWASP API Security Top 10
- OWASP Cheat Sheet Series
- CWE
- CAPEC
- MITRE ATT&CK
- NIST SP 800-53

Important distinction:

- `OWASP`, `CWE`, `ATT&CK`, `CAPEC`, and `NIST` are source datasets or publications
- `STRIDE` is a reasoning model that Owlvex should formalize into its own curated profile

## Provenance Requirement

Grounded packs should be auditable, not just plausible.

That means curated entries should carry provenance metadata that answers:

- where the guidance came from
- whether the content was manually curated or AI-assisted
- whether a human reviewed it
- when it was last verified

Recommended rule:

- no production issue, mapping, remediation, or policy entry should ship without populated provenance metadata
- policy templates should be treated as grounded product intelligence: source-backed, reviewed, versioned, and delivered as packs rather than improvised ad hoc in client code

Suggested validation path:

- `node tools/validate-grounded-data.mjs`
- `node tools/validate-grounded-data.mjs --strict`
