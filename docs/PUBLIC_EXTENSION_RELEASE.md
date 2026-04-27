# Public Extension Release

This document defines the minimal public GitHub distribution path for the production Owlvex VS Code extension while the main product repository remains private.

## Goal

Expose only:

- the production `.vsix`
- a public README
- licence and changelog text
- minimal release metadata

Do not expose the private product repository, backend code, benchmark assets, or internal docs.

## Operating Model

The private `CodeScanner` repository remains the source of truth.

Public GitHub distribution should happen through a separate public repository that contains:

- `README.md`
- `LICENSE.txt`
- `CHANGELOG.md`
- `downloads/owlvex-prod.vsix.sha256`
- `latest.json`
- `releases/owlvex-<version>.vsix` for users browsing the repository file tree
- GitHub Releases containing `owlvex-prod.vsix`

The production extension artifact is still built in the private repo, then published outward.

## Workflow

Use:

- `.github/workflows/publish-extension-public.yml`

That workflow:

1. checks out the private repo
2. runs `npm ci` in `extension/`
3. runs `npm run package:prod`
4. prepares a public bundle from:
   - `extension/profiles/prod.README.md`
   - `extension/LICENSE.txt`
   - `extension/CHANGELOG.md`
   - the packaged `owlvex-prod.vsix`
5. syncs the public README/metadata files into the public repo
6. publishes the `.vsix` and checksum as a GitHub release in the public repo

If publishing manually, also copy the production VSIX into `releases/owlvex-<version>.vsix` and set `latest.json.repositoryAsset` to that path. GitHub Releases remain the canonical download surface, but the checked-in `releases/` folder prevents the public repo code view from looking stale.

## Required GitHub Secrets

Add these secrets in the private repository:

- `PUBLIC_EXTENSION_REPO`
  - format: `owner/repo`
  - example: `owlvex/owlvex-extension`
- `PUBLIC_EXTENSION_REPO_TOKEN`
  - GitHub token with permission to push commits and create releases in the public repo

## Release Rule

The public repo should only receive:

- production extension artifacts
- production-facing README content
- release metadata for download and verification

It must not be used as a mirror of the full private repository.

## Recommended Public Repo Shape

Suggested repository purpose:

- name it specifically for the extension, not the whole product platform
- keep the root simple and download-oriented
- treat Releases as the primary download surface

Suggested structure:

```text
README.md
LICENSE.txt
CHANGELOG.md
latest.json
downloads/
  owlvex-prod.vsix.sha256
releases/
  owlvex-<version>.vsix
```

## Prototype Positioning

The public README should continue to state clearly that:

- Owlvex is still a prototype
- results can vary by provider/model
- important findings still require human verification
- some limitations are known and documented
- AI confidence is not proof; finder-only AI findings must be described as finder-only or not independently verified
- `Validated by AI review` should only describe findings with verifier or skeptic support
- framework selection is a scan lens for AI grounding, report emphasis, remediation variants, and expanded mapping detail, not a hard disable switch for deterministic security evidence
- reports may show canonical CWE, OWASP, MITRE, or NIST references for a finding even when that framework was not selected; those are taxonomy mappings, not proof that all framework lenses were active

## Bottom Line

This path makes the production extension downloadable from GitHub without making the full private product repository public.
