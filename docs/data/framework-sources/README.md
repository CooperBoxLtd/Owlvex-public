# Framework Sources

This directory holds raw upstream framework material that Owlvex can later distill into curated packs for AI-assisted reasoning and mapping.

Current intent:

- keep official upstream sources local for repeatable curation work
- avoid treating raw framework documents as direct prompt text
- keep a clear distinction between downloaded upstream material and Owlvex-authored canonical packs

Contents:

- `raw/` downloaded upstream files
- `download-status.json` latest fetch status for scripted downloads

This now also includes a local mirror of the OWASP Cheat Sheet Series pages used by Owlvex issue and remediation packs.

Notes:

- some sources are intentionally `source-only` for now because automated download was blocked from this environment or because licensing review should happen before mirroring bulk content
- use [tools/download-framework-sources.mjs](D:/Dev/repos/CodeScanner/tools/download-framework-sources.mjs) to refresh the downloaded set
