# Owlvex

Owlvex is a Visual Studio Code extension for early security review in the editor.

It scans code using deterministic local checks and optional AI-assisted review, then helps developers inspect findings and preview fixes before applying them.

## Download

Download the current prototype build:

- [owlvex-0.1.4.vsix](releases/owlvex-0.1.4.vsix)

SHA256:

```text
525ED5362A3AB5402083125793A6A2236027C699FD803B5303DAEF7E801524C0
```

## Install

1. Download `owlvex-0.1.4.vsix`.
2. Open VS Code.
3. Open the command palette.
4. Run `Extensions: Install from VSIX...`.
5. Select the downloaded file.

You can also install from a terminal:

```powershell
code --install-extension .\releases\owlvex-0.1.4.vsix
```

## What it does

- scans the current file, selected files, open editors, or workspace
- creates security reports
- supports OWASP, STRIDE, MITRE, CWE, and clean-code review modes
- supports optional AI providers using your own configured credentials
- supports project context for more grounded AI review
- lets you review generated fixes before applying them

## Prototype status

Owlvex is currently a prototype build. Findings should be reviewed before they are trusted or committed.

We are especially looking for feedback on:

- missed findings
- false positives
- slow or throttled AI scans
- confusing report output
- fix previews that should be safer or clearer

## Source

The source repository is private during early development. This public repository is only for the downloadable VS Code extension package and usage notes.
