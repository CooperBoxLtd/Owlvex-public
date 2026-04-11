# Owlvex

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

Every `⚡` finding is a proven structural violation. If the rule fires, the defect exists.

---

## Try it in 60 seconds

```bash
npm install -g owlvex
owlvex scan .
```

No config files. No API keys. No network calls. Node 18+ required.

---

## What it detects

| Rule | Finding | Trigger |
|------|---------|---------|
| `GR-001` | Command/shell injection | Template literal interpolated into `exec()`, `spawn()` |
| `SQ-001` | SQL injection | Template literal interpolated into `.query()`, `.execute()` |
| `SQ-005` | Ineffective sanitizer | HTML sanitizer applied before SQL sink |
| `AC-001` | Insecure Direct Object Reference | Caller-supplied ID in query, no ownership constraint |
| `AC-T001` | Multi-tenant isolation failure | `tenantId` accepted but absent from query WHERE clause |
| `DP-001` | PII in logger | Sensitive field (`password`, `ssn`, `accessToken`) passed to log call |
| `SM-001` | Insecure cookie | `res.cookie()` missing `httpOnly: true` |
| `SM-002` | Debug mode in production | `app.set('debug', true)` without `NODE_ENV !== 'production'` guard |

Rules only fire when an invariant is verifiably violated. When the condition is absent, the rule stays silent.

---

## Commands

```bash
owlvex scan .                                        # terminal output
owlvex scan ./src --report security-report.md       # write markdown report
owlvex scan ./src --fail-on deterministic           # exit 1 on findings (CI gate)
owlvex scan ./src --json                             # structured JSON output
```

---

## CI integration

```yaml
- name: Owlvex security gate
  run: |
    npm install -g owlvex
    owlvex scan . --fail-on deterministic
```

Pull requests that introduce a proven vulnerability fail. Pull requests that don't, pass cleanly. Copy the [full example workflow](.github/workflows/owlvex-example.yml) into your repo.

---

## Reports

`--report` produces a markdown report with an Attack Surface Assessment paragraph, a severity-sorted findings table, and per-finding detail — what was observed structurally, what an attacker can do, and exact remediation code.

---

## How it works

Owlvex reasons about structural invariants — the relationship between data flow, authorization, and dangerous operations. It doesn't match patterns against a known-bad list. It proves a specific combination of structural facts makes the defect certain.

Example: AC-001 fires when a caller-supplied parameter reaches a database query *and* no ownership constraint or authorization check appears in the function body. Remove either condition and the rule is silent.

This is why there are no false positives for the covered rules. The rule only fires when the invariant is verifiably broken.

---

## VS Code extension

Owlvex also ships as a VS Code extension with AI-assisted coverage for patterns that can't be proven structurally. Deterministic findings surface first, before AI results, with explicit provenance on every finding.

---

## Project layout

```
cli/              CLI entry point and bundle
extension/        VS Code extension (TypeScript)
backend/          Licence and billing backend (FastAPI)
tools/
  owlvex-benchmark/   Deterministic correctness gate (19 suites)
  demo/               Demo fixtures and script
```

## Build Direction

The current architecture and implementation contract are defined in [docs/IMPLEMENTATION_DESIGN.md](docs/IMPLEMENTATION_DESIGN.md).

The concrete implementation backlog derived from that design lives in [docs/IMPLEMENTATION_BACKLOG.md](docs/IMPLEMENTATION_BACKLOG.md).

That document is the source of truth for:

- local-vs-backend execution boundaries
- what Owlvex backend is allowed to do
- how deterministic and AI findings must coexist
- how future work should be implemented without breaking the product model

---

## Development

### Run tests

```bash
cd extension && npm install && npm test
```

### Run the benchmark gate

```bash
cd extension && npm run benchmark:deterministic
```

19 suites, covering all 8 rules across three reasoning axes. All must pass before any rule change ships.

### Build the CLI bundle

```bash
cd cli && npm install && npm run build
node cli/dist/owlvex.mjs scan .
```

### Run the extension locally

```bash
cd extension && npm install && npm run compile
```

Open `extension/` in VS Code and press `F5`.

### Start the backend (Docker)

```bash
cp backend/.env.example backend/.env
# edit backend/.env — set DATABASE_URL, SECRET_KEY, ADMIN_KEY
docker compose up -d
curl http://localhost:8000/health
```

---

## License

MIT
