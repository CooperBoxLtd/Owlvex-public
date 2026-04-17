# Owlvex Demo Runbook

This runbook is the shortest safe path for a live demo.

## Demo Goal

Show Owlvex as a developer-facing product that can:

- scan code
- explain risk clearly
- generate a remediation diff
- let the user keep or discard the fix
- verify the result after apply

Keep the story product-first and avoid deep scanner internals unless asked.

## Primary Demo Path

Use the controlled fixture flow first.

### Recommended Files

- unsafe: `tools/demo/01-idor-unsafe.js`
- safe companion: `tools/demo/02-idor-safe.js`

### Story

1. Open the Owlvex panel in VS Code.
2. Scan the two selected files.
3. Show that only `01-idor-unsafe.js` is flagged.
4. Open the top finding in sidebar/chat.
5. Explain the score and say:
   - file risk score tells us what to fix first
   - the top finding is an object-level authorization bug
6. Click `Fix code`.
7. Show the side-by-side diff.
8. Click `Keep fix`.
9. Let Owlvex verify the file after apply.
10. Point out that the safe companion was already clean.

### Presenter Notes

- emphasize "reviewable diff" and "verification after apply"
- keep the first path deterministic and low-risk
- avoid opening large reports first

## Secondary Demo Path

Use `tools/demo-app` only after the primary path lands cleanly.

### What To Show

- project context exists and can be edited locally
- Owlvex shows analysis mode and evidence posture
- deterministic findings and AI-backed findings are labeled differently

### Good Targets

- `src/lib/logger.js`
- `src/db.js`

Use `logger.js` when you want the cleanest `Static proof` example.

## Fallback Paths

If quota, latency, or AI behavior gets awkward:

1. Fall back to the deterministic fixture path.
2. Use an already generated report:
   - `tools/demo/owlvex-scan-report-20260416-222605.md`
   - `tools/demo-app/owlvex-scan-report-20260416-222605.md`
3. Show the `Fix code` flow from an existing finding instead of rescanning.

## Phrases To Use

- "Owlvex keeps the code in the client workflow and shows how it analyzed the result."
- "This finding is reviewable, not a blind auto-change."
- "The file risk score follows the highest remaining issue, so the next step is obvious."
- "Static proof and AI review are shown differently on purpose."

## Phrases To Avoid

- "100% accurate"
- "guaranteed secure"
- "it finds everything"

## Pre-Demo Checklist

- install the latest VSIX
- confirm the provider/model is the intended one
- open the Owlvex panel once before presenting
- have `tools/demo` files ready in the editor
- keep one fresh report available as backup

