# Owlvex — AI Code Security Scanner

Owlvex is a VS Code extension that scans your code against OWASP, STRIDE, MITRE, CWE, Clean Code, NIST, PCI-DSS, and HIPAA using your own AI provider. Code never leaves your machine.

## Pitch

Owlvex is building the developer-native layer for AI-powered application security. Instead of forcing teams into heavyweight security platforms or generic AI chat tools, Owlvex brings framework-aware vulnerability scanning directly into VS Code, using the customer's own model stack and keeping source code off Owlvex servers.

In one line:

**Owlvex gives software teams a developer-first AppSec product: AI-powered code security scanning inside VS Code, grounded in frameworks like OWASP and STRIDE, powered by the customer's own models.**

For fuller product documentation, see [docs/PRODUCT.md](docs/PRODUCT.md).
For the canonical security knowledge model, see [docs/KNOWLEDGE_MODEL.md](docs/KNOWLEDGE_MODEL.md).
For the issue catalog growth plan, see [docs/ISSUE_EXPANSION_ROADMAP.md](docs/ISSUE_EXPANSION_ROADMAP.md).
For the first curated rule pack, see [docs/data/issues/owlvex-issue-pack.v1.json](docs/data/issues/owlvex-issue-pack.v1.json).
For the first family-aware benchmark set, see [corpus/README.md](corpus/README.md) and [corpus/manifest.json](corpus/manifest.json).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Developer Machine                                       │
│                                                         │
│  ┌─────────────┐   1. validate licence    ┌──────────┐  │
│  │ VS Code     │ ────────────────────────▶│ Owlvex   │  │
│  │ Extension   │   2. fetch system prompt │ Backend  │  │
│  │             │ ◀────────────────────────│ (FastAPI)│  │
│  │             │                          └──────────┘  │
│  │             │   3. send code + prompt               │
│  │             │ ────────────────────────▶ AI Provider  │
│  │             │   4. receive findings    (OpenAI etc.) │
│  │             │ ◀────────────────────────              │
│  │             │   5. record metadata only              │
│  │             │ ────────────────────────▶ Backend      │
│  └─────────────┘      (no code sent)                    │
└─────────────────────────────────────────────────────────┘
```

**Code is never sent to the backend.** Only file hash, language, model, score, and finding counts are recorded.

---

## Components

| Component | Path | Tech |
|-----------|------|------|
| VS Code Extension | `extension/` | TypeScript 5.3 |
| Backend API | `backend/` | FastAPI + Python 3.12 |
| Database | `postgres/` | PostgreSQL 16 |
| Init SQL | `postgres/init/` | Schema + seed data |

---

## Quick Start (Local Development)

### Prerequisites

- Docker + Docker Compose
- Node.js 20+
- Python 3.12+

### 1. Configure environment

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and set at minimum:

```env
DATABASE_URL=postgresql+asyncpg://owlvex:owlvex@localhost:5432/owlvex
SECRET_KEY=change-me-to-a-random-string
ADMIN_KEY=change-me-to-another-random-string
ENVIRONMENT=development
```

### 2. Start the backend

```bash
docker compose up -d
```

This starts:
- PostgreSQL 16 on port 5432 (dev only, via override)
- FastAPI backend on `http://owlvex.local` (Traefik) or `http://localhost:8000`
- Ollama on `127.0.0.1:11434` on the Docker host for local use or SSH tunneling

The database schema and seed data are applied automatically from `postgres/init/`.

### 3. Verify the backend

```bash
curl http://localhost:8000/health
# {"status":"ok","environment":"development"}
```

### 4. Pull an Ollama model

```bash
docker compose exec ollama ollama pull qwen2.5:7b
```

### 5. Build and run the extension

```bash
cd extension
npm install
npm run compile
```

Open `extension/` in VS Code and press `F5` to launch the Extension Development Host.

### 6. Connect from your Windows machine

For the full scan flow:
- Set `owlvex.apiUrl` to `http://owlvex.local` so the extension reaches the backend through Traefik.
- Set `owlvex.provider` to `ollama`.
- Set `owlvex.ollama.host` to `http://localhost:11434`.

If VS Code is running on a different machine than Docker, tunnel to the stable host port on `ml30`:

```bash
ssh -L 11434:127.0.0.1:11434 cristian@192.168.50.35 -N
```

This avoids depending on a changing Docker container IP.

---

## Configuration (VS Code)

| Setting | Default | Description |
|---------|---------|-------------|
| `owlvex.apiUrl` | `http://owlvex.local` | Backend URL |
| `owlvex.provider` | `openai` | AI provider |
| `owlvex.frameworks` | `["OWASP","STRIDE"]` | Security frameworks |
| `owlvex.scanOnSave` | `false` | Auto-scan on file save |
| `owlvex.severityThreshold` | `MEDIUM` | Minimum severity to show |
| `owlvex.teamContext` | `""` | Project context appended to every prompt |
| `owlvex.foundry.endpoint` | `""` | Azure AI Foundry endpoint URL |
| `owlvex.ollama.host` | `http://localhost:11434` | Ollama host |
| `owlvex.custom.baseUrl` | `""` | Custom OpenAI-compatible endpoint |
| `owlvex.custom.model` | `""` | Model name for custom endpoint |

---

## AI Providers

| Provider | ID | Notes |
|----------|----|-------|
| OpenAI | `openai` | GPT-4o, o1, o3-mini |
| Anthropic | `anthropic` | Claude Opus/Sonnet/Haiku |
| Azure AI Foundry | `azure-foundry` | Requires endpoint URL |
| Mistral | `mistral` | mistral-large, codestral |
| Google Gemini | `gemini` | Gemini 1.5 Pro/Flash |
| Groq | `groq` | LLaMA 3.3, Mixtral (fast inference) |
| Ollama | `ollama` | Local, no API key required |
| Custom | `custom` | Any OpenAI-compatible endpoint |

Set up an AI connection via **Owlvex: Setup AI Connection** in the Command Palette.

---

## Commands

| Command | Description |
|---------|-------------|
| `Owlvex: Enter Licence Key` | Activate with your licence key |
| `Owlvex: Scan Current File` | Scan the active editor file |
| `Owlvex: Scan Workspace` | Scan all supported files (up to 500) |
| `Owlvex: Compare Scans` | Diff two scans by ID |
| `Owlvex: Switch AI Model` | Change model for the active provider |
| `Owlvex: Setup AI Connection` | Store API key for the active provider |

---

## Manual Testing And Probe Files

Owlvex includes two lightweight test paths that make it easier to validate scanning, reporting, and comparison without using a large real repository.

### 1. Local swap-based test files

Use the files in `tmp/` when you want a fast before/after demo from a single file:

- `tmp/owlvex-manual-test.js`
  Risky version with intentional issues.
- `tmp/owlvex-manual-test.safe.js`
  Safer version for the same scenario.
- `tmp/owlvex-manual-test.current.js`
  Active file to scan.
- `tmp/use-risky-test.ps1`
  Copies the risky version into `owlvex-manual-test.current.js`.
- `tmp/use-safe-test.ps1`
  Copies the safer version into `owlvex-manual-test.current.js`.

Typical flow:

1. Run `tmp/use-risky-test.ps1`.
2. Use `Owlvex: Scan Current File` and select `tmp/owlvex-manual-test.current.js`.
3. Create a report from the last scan.
4. Run `tmp/use-safe-test.ps1`.
5. Scan the same file again.
6. Use `Owlvex: Compare Scans` to validate the canonical before/after delta.

### 2. Probe folder for small repo-style scans

Use the probe folder when you want a tight folder scan with obvious issue types:

- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-hardcoded-secret.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-command-injection.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-sql-injection.js`
- `D:\Dev\repos\Morse App\src\probes\owlvex-probe-safe-baseline.js`

Recommended flow:

1. Use `Owlvex: Scan Folder`.
2. Select `D:\Dev\repos\Morse App\src\probes`.
3. Review the canonical findings and report output.
4. Fix or swap one probe.
5. Rescan the same folder.
6. Compare scans to see issue reduction by canonical ID.

### 3. Family-aware golden corpus

Use the `corpus/` folder when you want deterministic checks for canonical issue resolution and issue-family accuracy.

- `corpus/manifest.json`
  Expected canonical issues and expected issue family for each case.
- `corpus/README.md`
  Explains corpus structure and purpose.
- `corpus/<family>/positive/`
  Cases that should resolve to one or more canonical issues.
- `corpus/<family>/negative/`
  Cases that should stay unresolved or avoid a known false positive.

The first corpus version is intentionally practical:

- 20 files
- positive and negative cases
- coverage across secrets, injection, identity/auth, access control, data protection/privacy, and crypto/randomness

This corpus is meant to validate Owlvex at two levels:

1. `Issue-level accuracy`
   Did Owlvex resolve to the right canonical issue ID?
2. `Family-level accuracy`
   Even if the exact subtype is imperfect, did Owlvex land in the correct risk domain?

### What These Files Are For

- `tmp/` is for repeatable single-file demos and quick scanner smoke tests.
- `src/probes/` is for small folder scans, reporting, and comparison demos.
- Generated `owlvex-scan-report-*.md` files in the probe folder are output artifacts, not source fixtures.

For product and demo positioning, see [docs/PRODUCT.md](docs/PRODUCT.md).

---

## Security Frameworks

| Framework | Code | Plan |
|-----------|------|------|
| OWASP Top 10 (2021) | `OWASP` | Free |
| STRIDE Threat Model | `STRIDE` | Developer |
| MITRE ATT&CK | `MITRE` | Developer |
| CWE Top Weaknesses | `CWE` | Developer |
| Clean Code Principles | `CLEANCODE` | Developer |
| NIST 800-53 | `NIST` | Team |
| PCI-DSS 4.0 | `PCIDSS` | Team |
| HIPAA Security Rule | `HIPAA` | Enterprise |

---

## Plans

| Feature | Developer | Team | Enterprise |
|---------|-----------|------|------------|
| OWASP + STRIDE + MITRE + CWE + CleanCode | ✓ | ✓ | ✓ |
| NIST + PCI-DSS | — | ✓ | ✓ |
| HIPAA | — | — | ✓ |
| Scan comparison | — | ✓ | ✓ |
| Team prompts | — | ✓ | ✓ |
| Prompt editor | — | ✓ | ✓ |
| CI/CD API | — | — | ✓ |
| PDF reports | — | — | ✓ |
| SSO | — | — | ✓ |
| Daily scan limit | 50 | 200 | Unlimited |

---

## API Endpoints

All endpoints are prefixed with `/v1`.

### `GET /health`
Returns backend status.

### `POST /v1/licences/validate`
Validates a licence key. Called by the extension on startup.
- Header: `X-Licence-Key: owlvex_lic_...`
- Body (optional): `{ "user_email": "..." }`

### `POST /v1/licences/generate` (admin)
Creates a new licence. Requires admin key.
- Header: `X-Admin-Key: <admin_key>`
- Body: `{ "team_name": "...", "email": "...", "plan": "developer|team|enterprise", "seats": 1 }`

### `POST /v1/prompts/build`
Returns an assembled system prompt for a scan.
- Header: `X-Licence-Key: owlvex_lic_...`
- Body: `{ "frameworks": ["OWASP"], "language": "python", "model": "gpt-4o", "severity_threshold": "MEDIUM", "team_context": "" }`

### `POST /v1/scans/record`
Records scan metadata (no code).
- Header: `X-Licence-Key: owlvex_lic_...`
- Body: file hash, score, findings summary, model, provider, frameworks

### `POST /v1/scans/compare`
Diffs two scans.
- Header: `X-Licence-Key: owlvex_lic_...`
- Body: `{ "scan_a_id": "...", "scan_b_id": "..." }`

### `POST /v1/billing/webhook/stripe`
Stripe webhook handler. Requires `Stripe-Signature` header.

---

## Development

### Backend tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

### Extension tests

```bash
cd extension
npm install
npm test
```

### Generate a dev licence key manually

```bash
curl -X POST http://localhost:8000/v1/licences/generate \
  -H "X-Admin-Key: <your_admin_key>" \
  -H "Content-Type: application/json" \
  -d '{"team_name":"Dev","email":"dev@local","plan":"team","seats":5}'
```

The response includes `raw_key` — store it, it is not retrievable again.

---

## Production Deployment

### Environment variables required

```env
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/owlvex
SECRET_KEY=<random 64 char string>
ADMIN_KEY=<random 64 char string>
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_DEVELOPER_MONTHLY=price_...
STRIPE_PRICE_DEVELOPER_ANNUAL=price_...
STRIPE_PRICE_TEAM_MONTHLY=price_...
STRIPE_PRICE_TEAM_ANNUAL=price_...
SENDGRID_API_KEY=SG....
FROM_EMAIL=noreply@owlvex.io
ENVIRONMENT=production
```

### Stripe setup

1. Create products and prices in the Stripe dashboard
2. Set the four `STRIPE_PRICE_*` env vars to the corresponding price IDs
3. Create a webhook pointing to `https://your-domain/v1/billing/webhook/stripe`
4. Set `STRIPE_WEBHOOK_SECRET` to the webhook signing secret
5. Pass `metadata.plan` and `metadata.seats` in Stripe Checkout session creation

### Packaging the extension

```bash
cd extension
npm install
npm run package
# Produces owlvex-0.1.0.vsix
```

Install with: `code --install-extension owlvex-0.1.0.vsix`

---

## Dev Test Licence

The seed data includes a development licence for local testing:

```
Key: owlvex_lic_DEV_TEST_KEY_FOR_LOCAL_USE_ONLY
Plan: team
Expires: 2030-01-01
```

**Do not use this key in production.**
