# Owlvex Public Repository Publication Policy

This repository is only for publishing the production Owlvex VS Code extension package and minimal public release metadata.

## Allowed content

Only these categories may be committed here:

- production VSIX package files, for example `downloads/owlvex-prod-0.8.0.vsix`
- versioned production VSIX copies under `releases/vX.Y.Z/`
- public release metadata, for example `latest.json`
- public README, changelog, support, and licence files
- repository guard workflow files under `.github/workflows/`
- this publication policy

## Forbidden content

Never commit or push any of the following to this repository:

- extension source code, including `src/`, `package.json`, `package-lock.json`, `tsconfig.json`, or build scripts
- backend, portal, infrastructure, database, benchmark, corpus, or internal tooling folders
- private documentation, design reports, implementation plans, architecture notes, or internal product strategy
- secrets, keys, `.env` files, local configuration, credentials, tokens, or customer data
- development VSIX packages such as `owlvex-dev.vsix`
- generated local reports or scan output

## Required publishing procedure

Before pushing to this repository:

1. Build and verify the production extension package in the private product repository.
2. Copy only the production VSIX into this distribution repository.
3. Update `latest.json`, `README.md`, and `CHANGELOG.md` if the version changed.
4. Confirm the tree contains only allowed public distribution files.
5. Confirm the package name is `owlvex-prod-<version>.vsix` or a versioned release copy of the same production package.
6. Do not push branches, tags, or history copied from the private product repository.

## Verification commands

Run these checks before every push:

```powershell
git ls-tree -r --name-only HEAD
git log --oneline --decorate --max-count=5
Get-FileHash -Algorithm SHA256 .\downloads\owlvex-prod-0.8.0.vsix
```

The tree must not include `src`, `backend`, `portal`, `infra`, `tools`, `extension`, `package.json`, or development packages.

## Emergency response

If forbidden content is pushed here:

1. Make the repository private immediately.
2. Delete exposed refs and tags.
3. Rotate any exposed secrets.
4. Recreate the repository from a clean root commit if needed.
5. Publish only the production VSIX and public metadata again.
