# Changelog

## 0.1.23

- add local CSRF fallback evidence for authenticated repository mutations when AI omits the route finding
- keep cookie-reading auth middleware out of promoted CSRF findings unless a state-changing route is proven
- clarify AI review paths when verifier or skeptic passes return no verdict
- disambiguate repeated audit findings with source/sink anchors in reports
- improve report wording for safe-probe and finder-only evidence posture

## 0.1.21

- make report confidence wording explicit for AI-backed findings
- show final raw AI confidence in report tables and finding details
- show the AI review path (`finder`, `finder+verifier`, or `finder+verifier+skeptic`)
- reserve `Validated by AI review` for findings with verifier or skeptic support
- label finder-only high-confidence findings as not independently verified

## 0.1.20

- continue fix workflows when post-fix verification still finds unresolved issues
- make remaining or newly surfaced findings the next active fix target after verification
- add clearer post-fix continuation wording and next-fix actions

## 0.1.18

- add Engine 1.0 proof-contract evidence for SSRF across JavaScript, Python, Java, C#, and Go
- add a proof-contract benchmark gate for source, sink, guard, verdict, rationale, and safe companion behavior
- add family-specific deterministic evidence contracts for remaining covered rule families
- add benchmark direction metrics for pass rate, unsafe recall, safe quietness, evidence-shape completeness, and fixture growth
- surface Engine evidence contract coverage, missing guards, and AI-only gaps in generated reports
- surface Engine evidence posture in scan chat summaries, sidebar details, and the status bar tooltip
- expand proof-contract benchmarks with safe companions for path traversal, command execution, SQL, and client-controlled query filters

## 0.1.17

- save kept fix previews before verification rescans so the next scan reads the persisted code
- label broad fix requests as findings across files instead of miscounting findings as files
- make clean scan and post-fix verification messages provider/model-scoped
- capture provider disagreement when a later model finds issues after another model reported a clean file
- replace pseudo-precise report confidence headlines with qualitative AI signal bands and evidence confidence

## 0.1.16

- add a first-run chat empty state focused on the first 60 seconds of use
- surface setup readiness for access, project/workspace, LLM configuration, and first scan
- promote `Use Free` and `Start Trial` into visible onboarding actions
- make the LLM rail button say `Configure LLM` until a provider is ready
- label report creation as `Report after scan` before a scan exists
- rename fix actions from `Fix code` / `Fix scan broadly` to `Preview fix` / `Preview fixes` so users know fixes open reviewable diffs before files change
- package and publish production build `0.1.16`

## 0.1.4

- remove the remaining actionable-finding truncation so broad workspace fixes use the full fixable set instead of the top three results

## 0.1.3

- remove the combined fix preview file cap so broad workspace fixes can include the full actionable set

## 0.1.2

- update the Marketplace package and README guidance for the first public release

## 0.1.1

- persist validated licence state across workspace and repo switches
- reduce unnecessary chat webview reloads and harden view lifecycle handling
- simplify the primary actions shown in the chat settings panel
- improve admin environment switch persistence in linked backend flows
- package repeatable Marketplace publish commands for prod and dev builds

## 0.1.0

- initial prototype release
