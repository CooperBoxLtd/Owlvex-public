# Dev Observability Telemetry Plan

This plan defines the next dev-only telemetry workstream for Owlvex.

It starts after the Engine 1.0 evidence sprint. The goal is to measure whether the product and engine are improving without weakening the core privacy boundary: Owlvex backend must not receive raw source code, snippets, prompts, provider transcripts, file paths, or finding text through telemetry.

## Branch

Work should start on:

```text
dev-observability-telemetry
```

The branch is intentionally separate from `engine-1.0-evidence-sprint`, which is treated as finished for this line of work.

## Goal

Build a dev-only observability layer that can answer:

- how many scans are being run
- which scan scopes users choose
- how long scans and fix workflows take
- where time is spent inside a scan
- which provider/model is being used
- which internal agent role is active
- how often scans, reports, and fixes fail
- how often fix previews are applied, discarded, or verified
- whether post-fix verification actually removes the targeted finding
- whether verifier, skeptic, safe probes, and caller-path work improve quality enough to justify latency/cost

This is not a source-code collection feature.

## Existing Foundation

The repo already has the required basic shape:

- backend model: `UsageEvent`
- backend table: `usage_events`
- backend endpoint: `POST /v1/usage/events`
- backend scalar metadata allowlist in `backend/app/routers/usage.py`
- extension helper: `trackUsageEvent(...)`
- existing events such as:
  - `scan_run`
  - `finding_viewed`
  - `fix_viewed`
  - `fix_preview_generated`
  - `fix_preview_applied`
  - `fix_verification_completed`
  - `registration_verified`
  - provider/model selection events

The next step is to make this richer, more explicit, and dev-profile gated.

## Dev-Only Boundary

Initial implementation must be dev only:

- package: `Owlvex Dev`
- backend: Azure dev
- environment: `ENVIRONMENT=development`
- telemetry profile: `dev_observability`
- production behaviour: unchanged unless later promoted deliberately

Production should either ignore dev-only fields or reject dev-only profile use until a separate product decision is made.

## Telemetry Profiles

Do not introduce separate licence types yet. Add a telemetry profile as licence/customer metadata, preferably inside licence `features` first:

```json
{
  "telemetry_profile": "dev_observability"
}
```

Initial profiles:

- `standard`
- `dev_observability`

Rules:

- free/trial can still require standard telemetry.
- paid licences can still opt out of optional product telemetry.
- dev observability is an additional profile, not a replacement for plan semantics.
- `dev_observability` should only be honoured when the backend environment is `development`.

## Event Names

Add these dev observability events:

- `scan_started`
- `scan_completed`
- `scan_failed`
- `report_created`
- `report_failed`
- `fix_preview_started`
- `fix_preview_completed`
- `fix_preview_failed`
- `fix_applied`
- `fix_discarded`
- `post_fix_scan_completed`

Keep existing event names for compatibility. The new names are lifecycle events with timings.

## Shared Metadata Fields

Allow these scalar metadata fields for dev observability events:

- `telemetry_profile`
- `scope`
- `status`
- `stage`
- `error_kind`
- `provider`
- `model`
- `agent_mode`
- `analysis_mix`
- `file_count`
- `finding_count`
- `risk_score`
- `risk_before`
- `risk_after`
- `target_removed`
- `duration_ms`
- `queue_ms`
- `read_files_ms`
- `deterministic_ms`
- `ai_review_ms`
- `verifier_ms`
- `skeptic_ms`
- `safe_probe_ms`
- `caller_path_ms`
- `report_ms`
- `fix_preview_ms`
- `post_fix_verify_ms`

All fields must stay scalar: string, number, boolean, or null. No arrays or objects in the first slice.

## Scan Scope Values

Use stable string values:

- `current_file`
- `selected_files`
- `open_editors`
- `changed_files`
- `workspace`
- `benchmark`

## Agent Mode Values

Use role labels, not prompt text:

- `deterministic_only`
- `finder`
- `verifier`
- `skeptic`
- `safe_probe`
- `caller_path`
- `fix_preview`
- `report_summary`
- `chat_advisory`

## Analysis Mix Values

Use compact composition strings:

- `deterministic`
- `deterministic+finder`
- `deterministic+finder+verifier`
- `deterministic+finder+verifier+skeptic`
- `deterministic+finder+safe_probe`
- `deterministic+finder+safe_probe+caller_path`

The exact values can expand later, but they should remain bounded and documented.

## Timing Model

The extension should record total duration for every lifecycle event and specific timing buckets where available.

Suggested scan timing buckets:

```json
{
  "duration_ms": 18420,
  "queue_ms": 120,
  "read_files_ms": 310,
  "deterministic_ms": 220,
  "ai_review_ms": 14300,
  "verifier_ms": 2100,
  "skeptic_ms": 900,
  "safe_probe_ms": 180,
  "caller_path_ms": 120,
  "report_ms": 410
}
```

Suggested fix timing buckets:

```json
{
  "fix_preview_ms": 6200,
  "post_fix_verify_ms": 1700,
  "duration_ms": 8000
}
```

If a bucket is unavailable, omit it. Do not invent precision.

## Failure Model

Use `scan_failed`, `report_failed`, and `fix_preview_failed` with:

- `stage`
- `error_kind`
- `duration_ms`
- `provider`
- `model`
- `scope`

Initial `stage` values:

- `read_files`
- `deterministic`
- `provider_call`
- `provider_parse`
- `verifier`
- `skeptic`
- `safe_probe`
- `caller_path`
- `report`
- `fix_preview`
- `post_fix_verify`

Initial `error_kind` values:

- `timeout`
- `rate_limit`
- `provider_error`
- `validation`
- `parse`
- `cancelled`
- `unknown`

Do not send exception messages until a redaction strategy exists.

## Example Events

Scan completed:

```json
{
  "event_name": "scan_completed",
  "metadata": {
    "telemetry_profile": "dev_observability",
    "scope": "workspace",
    "file_count": 12,
    "finding_count": 6,
    "duration_ms": 18420,
    "deterministic_ms": 220,
    "ai_review_ms": 14300,
    "provider": "openai",
    "model": "gpt-5.4",
    "agent_mode": "finder",
    "analysis_mix": "deterministic+finder+verifier",
    "status": "completed"
  }
}
```

Scan failed:

```json
{
  "event_name": "scan_failed",
  "metadata": {
    "telemetry_profile": "dev_observability",
    "scope": "selected_files",
    "stage": "provider_call",
    "error_kind": "timeout",
    "duration_ms": 30000,
    "provider": "anthropic",
    "model": "claude-sonnet",
    "status": "failed"
  }
}
```

Fix verification:

```json
{
  "event_name": "post_fix_scan_completed",
  "metadata": {
    "telemetry_profile": "dev_observability",
    "file_count": 1,
    "finding_count": 0,
    "risk_before": 9.0,
    "risk_after": 0.0,
    "target_removed": true,
    "post_fix_verify_ms": 1700,
    "status": "completed"
  }
}
```

## Backend Implementation Slices

### Slice 1: Contract

- Add `telemetry_profile` to licence features for dev-issued licences.
- Add an admin endpoint and console toggle to set a licence profile to `standard` or `dev_observability`.
- Add the new event names to `USAGE_EVENT_METADATA_FIELDS`.
- Add metadata allowlists for timing, provider/model, scope, status, agent role, and failure fields.
- Reject `dev_observability` telemetry when `ENVIRONMENT != development`.
- Keep metadata scalar-only.
- Add tests for accepted and rejected dev telemetry.

### Slice 2: Extension Emission

- Emit `scan_started`, `scan_completed`, and `scan_failed` from `Owlvex Dev` scan flows.
- Include provider/model through the existing registry path.
- Include scope and file count.
- Include total duration.
- Add deterministic/AI timing buckets where they can be measured honestly.

### Slice 3: Fix And Report Events

- Emit `report_created` and `report_failed`.
- Emit `fix_preview_started`, `fix_preview_completed`, `fix_preview_failed`.
- Emit `fix_applied`, `fix_discarded`, and `post_fix_scan_completed`.
- Include target-removed and risk-before/risk-after only when available.

### Slice 4: Admin Visibility

- Extend admin metrics/export views to group usage events by:
  - telemetry profile
  - event name
  - scope
  - provider
  - model
  - status
- Add simple aggregate measures:
  - count
  - average duration
  - failure count
  - failure rate

Implemented dashboard surface:

- Customer detail now has a **Telemetry Profile** callout.
- Operators can apply **Dev Observability** or revert to **Standard** from the selected customer.
- The callout explains the practical rule: this is for dev licences only, and the extension must revalidate or restart after the profile changes.
- Metrics now include a **Dev Observability** section with scan, report, fix-preview, fix-apply, post-fix scan, duration, provider/model, and failure-rate aggregates.
- Metrics export now supports `metrics_dev_observability`.

Practical operator workflow:

1. Open the dev admin console.
2. Select the customer/licence.
3. Click **Apply Dev Observability**.
4. In VS Code, revalidate/restart the dev extension so the cached licence receives `telemetry_profile=dev_observability`.
5. Run normal workflows: scan, create report, preview fix, keep/discard fix.
6. Open **Metrics** and refresh. Use **Group by customer** when validating one test account, or **Group by plan/provider exports** for broader analysis.
7. Revert to **Standard** when done.

## Acceptance Criteria

- Dev licences can be marked with `telemetry_profile=dev_observability`.
- Dev backend accepts the new lifecycle events.
- Production backend does not accept dev-only profile usage.
- Extension emits lifecycle events for at least current-file, selected-files, changed-files, open-editors, and workspace scans.
- Events include provider/model where applicable.
- Events include total duration.
- No source code, snippets, file paths, prompt text, or raw finding text are sent.
- Backend tests cover allowed fields, rejected fields, disabled telemetry, and dev-only profile enforcement.
- Admin export can answer basic direction questions:
  - are scans getting faster?
  - where are failures happening?
  - which model/provider is slow or failing?
  - which scan scope is most used?
  - do fixes resolve the target finding?

## Out Of Scope For First Slice

- production customer observability
- billing changes
- source upload
- prompt/transcript storage
- per-file path telemetry
- arrays/objects in telemetry metadata
- marketplace release
