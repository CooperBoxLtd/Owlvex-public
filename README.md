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

### Install from VS Code

1. Download [owlvex-0.1.4.vsix](releases/owlvex-0.1.4.vsix).
2. Open Visual Studio Code.
3. Open the command palette:
   - Windows/Linux: `Ctrl+Shift+P`
   - macOS: `Cmd+Shift+P`
4. Run `Extensions: Install from VSIX...`.
5. Select the downloaded `owlvex-0.1.4.vsix` file.
6. Reload VS Code if prompted.

After installation, Owlvex appears in the VS Code activity bar and its commands are available from the command palette.

### Install from terminal

You can also install from a terminal:

```powershell
code --install-extension .\releases\owlvex-0.1.4.vsix
```

If you downloaded the file to another folder, run the command from that folder or pass the full path to the `.vsix` file.

## First use

1. Open the project you want to scan in VS Code.
2. Open the command palette.
3. Run `Owlvex: Register Free Or Trial Access`.
4. Run `Owlvex: Setup AI Connection` if you want AI-assisted review.
5. Run one of the scan commands:
   - `Owlvex: Scan Current File`
   - `Owlvex: Scan Selected Files`
   - `Owlvex: Scan Open Editors`
   - `Owlvex: Scan Workspace`
   - `Owlvex: Create Report`

AI setup is optional. Local deterministic checks can still run without an AI provider, but AI-backed explanations, broader review, and fix assistance require a configured provider.

## Common commands

| Command | Use |
| --- | --- |
| `Owlvex: Scan Current File` | Scan the active editor file. |
| `Owlvex: Scan Selected Files` | Scan files selected in the VS Code explorer. |
| `Owlvex: Scan Workspace` | Scan the current workspace. |
| `Owlvex: Create Report` | Generate a markdown scan report. |
| `Owlvex: Open AI Chat` | Ask questions about the current project or findings. |
| `Owlvex: Review Fix` | Generate a fix preview for a finding. |
| `Owlvex: Apply Fix Preview` | Apply a reviewed fix preview. |
| `Owlvex: Select Project Root` | Set the project boundary used for workspace scans and repo context. |
| `Owlvex: Open Project Context` | Open or edit project context used to ground AI review. |
| `Owlvex: Switch AI Model` | Change the configured AI model. |

## Recommended workflow

1. Select the project root with `Owlvex: Select Project Root`.
2. Scan a small scope first, such as the current file or selected files.
3. Review the findings and generated report.
4. Use `Owlvex: Review Fix` to preview any proposed fix before applying it.
5. Re-scan after changing code to confirm the result.
6. Use workspace scans when the smaller flow is behaving as expected.

For larger repositories, start with selected files or open editors. AI-backed workspace scans can be slower depending on provider limits and throttling.

## Support and feedback

Owlvex is an early prototype, so support is focused on making the product usable and learning where it fails.

Contact support by opening a GitHub issue:

- [Open an Owlvex support issue](https://github.com/CooperBoxLtd/Owlvex-public/issues/new)

You can also contact support by email:

- info@cooperbox.co.uk

Use GitHub Issues for:

- installation problems
- extension activation errors
- scan failures
- incorrect findings
- missed findings
- confusing reports
- fix previews that look unsafe or incomplete
- AI provider setup problems

When opening an issue, include:

- your operating system
- VS Code version
- Owlvex version
- whether the issue happens with deterministic scanning, AI scanning, or both
- the command you ran
- any visible error message
- whether you are using OpenAI, Azure AI Foundry, Anthropic, Mistral, Gemini, Groq, Ollama, or a custom endpoint

Do not paste secrets, API keys, proprietary source code, or customer data into public issues. If a code sample is needed, reduce it to a small safe reproduction first.

For private or sensitive support requests, do not post details publicly. Email info@cooperbox.co.uk instead.

## AI provider setup

Owlvex supports several provider modes, including OpenAI, Azure AI Foundry, Anthropic, Mistral, Gemini, Groq, Ollama, and custom OpenAI-compatible endpoints.

To configure AI:

1. Run `Owlvex: Setup AI Connection`.
2. Choose your provider.
3. Enter the requested endpoint, model, or API key details.
4. Run `Owlvex: Test AI Connection`.

Credentials are stored using VS Code secret storage where applicable. Do not commit API keys or provider secrets into your project.

## What it does

- scans the current file, selected files, open editors, or workspace
- creates security reports
- supports OWASP, STRIDE, MITRE, CWE, and clean-code review modes
- supports optional AI providers using your own configured credentials
- supports project context for more grounded AI review
- lets you review generated fixes before applying them

## Updating Owlvex

To update from a newer `.vsix` file, download the new release and install it the same way:

```powershell
code --install-extension .\releases\owlvex-0.1.4.vsix --force
```

Then reload VS Code if prompted.

## Uninstall

1. Open the Extensions view in VS Code.
2. Search for `Owlvex`.
3. Select the extension.
4. Click `Uninstall`.
5. Reload VS Code if prompted.

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
