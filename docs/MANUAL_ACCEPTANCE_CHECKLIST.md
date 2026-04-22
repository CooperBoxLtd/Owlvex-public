# Owlvex Manual Acceptance Checklist

This checklist is the required human validation pass before calling an Owlvex build release-ready.

It exists because tests and CI gates do not prove that the real extension, backend, provider setup flows, and degraded-mode UX work together in a live operator session.

## Scope

Run this checklist against the current branch or release candidate using:

- a real VS Code window
- a live extension build from `extension/`
- a reachable backend for the online checks
- at least one backend-down/offline pass
- at least one real AI provider

Minimum provider matrix for manual validation:

- `openai` or another known-good provider
- `azure-foundry`
- `ollama` or one offline/local provider if available

## Preflight

1. Compile the extension.

```bash
cd extension
npm install
npm run compile
```

2. Verify the backend health endpoint for the online pass.

```bash
curl http://192.168.50.35:8000/health
```

or production:

```bash
curl https://owlvex-api.azurewebsites.net/health
```

The extension should use the packaged backend URL by default for the selected build. `Configure Backend Override URL` is only for intentional non-default environments or debugging.

3. Open `extension/` in VS Code and launch the extension host with `F5`.

4. Prepare a small workspace with at least:

- one file that should produce deterministic findings
- one file that should scan cleanly
- one file useful for report generation

## Activation And Basic UX

1. Confirm the extension activates on startup without a crash.

Pass:
- Owlvex activity bar icon appears
- findings tree appears
- AI chat webview opens
- no immediate activation exception appears in the extension host logs

2. Confirm commands are registered and visible.

Pass:
- `Owlvex: Scan Current File`
- `Owlvex: Scan Workspace`
- `Owlvex: Create Report`
- `Owlvex: Setup AI Connection`
- `Owlvex: Enter Licence Key`
- `Owlvex: Compare Scans`

## Licence And Pack Flow

1. Enter a valid licence key.

Pass:
- activation succeeds
- status bar changes out of unlicensed state
- no raw error is exposed to the user

2. Confirm pack fetch succeeds with backend available.

Pass:
- issue pack, mapping pack, remediation pack load without visible failure
- status/report/sidebar intelligence mode reflects fresh or cached pack usage appropriately

3. Restart the extension host and confirm cached pack reuse.

Pass:
- extension starts without refetch being strictly required
- cached or fresh mode is shown honestly

## Provider Setup

### Known-good provider

1. Configure `openai` or another known-good hosted provider.

Pass:
- setup flow stores the key
- connection test succeeds
- model selection works
- scan completes with AI-assisted output when expected

### Azure Foundry

1. Select provider `azure-foundry`.

2. Run `Owlvex: Setup AI Connection`.

3. Enter:

- a real endpoint like `https://<resource>.openai.azure.com`
- a real deployment name, not just a model family name unless they match
- a valid API key

Pass:
- setup fails if the deployment name does not exist
- setup succeeds when the deployment exists
- the success message reflects the configured deployment
- a real scan using Foundry completes successfully

Fail:
- setup says connected but scans later fail because the deployment name was ignored
- the extension silently falls back to `gpt-4o` when a custom deployment name was entered

### Offline/local provider

1. Configure `ollama` if available.

Pass:
- connection test succeeds when the local runtime is up
- scan completes without requiring hosted AI credentials

## Scan Flows

### Single-file scan

1. Run `Owlvex: Scan Current File` on a file with known deterministic issues.

Pass:
- findings appear in diagnostics
- findings appear in sidebar
- remediation details appear in the UI
- warnings, if any, are visible

2. Run the same command on a clean file.

Pass:
- no stale findings remain
- score and summary update correctly

### Scan on save

1. Enable `owlvex.scanOnSave`.
2. Save a file with a known deterministic issue.

Pass:
- scan runs automatically
- diagnostics/sidebar/status update without manual command invocation

### Workspace scan

1. Run `Owlvex: Scan Workspace`.

Pass:
- progress completes without crashing
- mixed file results are summarized correctly
- errors are surfaced cleanly if some files fail

### Report generation

1. Run `Owlvex: Create Report`.

Pass:
- report opens successfully
- canonical remediation appears
- framework-specific remediation appears where available
- intelligence-source mode is visible

### Comparison

1. Produce two scans and run `Owlvex: Compare Scans`.

Pass:
- comparison panel opens
- new/resolved findings counts are numeric and sane
- detail sections populate correctly

## Degraded And Offline Behavior

1. Stop or disconnect the backend.

2. Restart the extension host or trigger a new scan.

Pass:
- deterministic scanning still works
- extension falls back to cached packs or bundled mode instead of hard failing
- the UI makes degraded mode visible

3. Trigger a scan with the AI provider unavailable.

Pass:
- deterministic findings still return
- the user sees warnings rather than a total failure where possible

## Policy And Control-Plane Checks

1. Hit the policy evaluation flow against a reachable backend.

Pass:
- backend returns decisions cleanly
- no source code is sent to the backend
- only metadata and finding identifiers are used

2. Confirm the backend-only control-plane boundary.

Pass:
- no request body contains raw source content
- scans continue to execute locally

## Packaging Smoke Test

1. Build the dev package.

```bash
cd extension
npm run package:dev
```

2. Build the prod package.

```bash
cd extension
npm run package:prod
```

Pass:
- both packages build successfully
- the two package commands are run sequentially, not in parallel
- profile-specific defaults are correct
- backend is preconfigured automatically for each package profile without requiring manual setup

## Exit Criteria

Do not call a build release-ready until:

- all checklist sections relevant to the release were executed
- all failures were recorded
- all release-blocking failures were fixed and rerun

Minimum release note for this checklist:

- date
- tester
- branch or commit
- backend URL used
- providers tested
- failures found
- final pass/fail outcome
