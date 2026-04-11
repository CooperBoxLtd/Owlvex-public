# owlvex

**Deterministic security validation for JavaScript and TypeScript.**

Most security tools tell you what *might* be wrong. Owlvex tells you what is *proven* to be wrong — structural invariant violations with 100% confidence, no false positives, no configuration required.

```bash
npm install -g owlvex
owlvex scan .
```

---

## What it looks like

```
Owlvex — scanning 47 files...

  ⚡ AC-001   HIGH      src/api/documents.js:12
             Insecure Direct Object Reference
  ⚡ AC-T001  CRITICAL  src/api/tenants.js:34
             Multi-Tenant Isolation Failure
  ⚡ SQ-001   HIGH      src/db/search.js:8
             SQL Injection

  3 deterministic findings  |  47 files scanned
```

Every `⚡` finding is a proven structural violation — not a guess. If the rule fires, the defect exists.

---

## Install

```bash
npm install -g owlvex
```

Node 18+ required. No config files. No API keys. No network calls.

---

## Usage

```bash
# Scan a directory
owlvex scan .
owlvex scan ./src

# Write a markdown report
owlvex scan . --report security-report.md

# Exit 1 if findings exist (CI gate)
owlvex scan . --fail-on deterministic

# JSON output for tooling
owlvex scan . --json
```

---

## What it detects

| Rule | Finding | Trigger |
|------|---------|---------|
| `GR-001` | Command/shell injection | Template literal interpolated into `exec()`, `spawn()` |
| `SQ-001` | SQL injection | Template literal interpolated into `.query()`, `.execute()` |
| `SQ-005` | Ineffective sanitizer | HTML sanitizer applied before SQL sink |
| `AC-001` | Insecure Direct Object Reference | Caller-supplied ID in query, no ownership constraint |
| `AC-T001` | Multi-tenant isolation failure | `tenantId` accepted but absent from query `WHERE` clause |
| `DP-001` | PII in logger | Sensitive field (`password`, `ssn`, `accessToken`) passed to log call |
| `SM-001` | Insecure cookie | `res.cookie()` missing `httpOnly: true` |
| `SM-002` | Debug mode in production | `app.set('debug', true)` without `NODE_ENV !== 'production'` guard |

All rules are structural — they fire only when an invariant is *verifiably* violated. When the condition is not present, the rule stays silent.

---

## CI integration

Add to any GitHub Actions workflow:

```yaml
- name: Owlvex security gate
  run: |
    npm install -g owlvex
    owlvex scan . --fail-on deterministic
```

Pull requests that introduce a proven vulnerability fail the check. Pull requests that don't, pass cleanly.

For a complete copy-paste workflow, see the [example workflow](https://github.com/CooperBox/CodeScanner/blob/main/.github/workflows/owlvex-example.yml).

---

## How it's different

**Semgrep** matches code patterns you define. You write the rules; coverage depends on what you write.

**Snyk** matches known vulnerability signatures in dependencies. It doesn't reason about your application code.

**Owlvex** reasons about structural invariants in your application code — the relationship between data flow, authorization, and dangerous operations. It explains *why* a finding is a defect, not just *that* it matched a pattern.

The result: findings you can escalate immediately without additional validation.

---

## Report output

`--report` produces a markdown report with:

- **Attack Surface Assessment** — a deterministic narrative paragraph summarizing exposure
- **Deterministic Detections panel** — findings table sorted by severity
- **Per-finding detail** — what was observed structurally, what an attacker can do, exact remediation code

```bash
owlvex scan ./src --report security-report.md
```

---

## VS Code extension

Owlvex also runs as a VS Code extension with AI-assisted coverage for patterns that can't be proven structurally. Deterministic findings are surfaced first, before AI results, with explicit provenance labels on every finding.

---

## License

MIT
