# Owlvex Security And Data Boundary

Date: 2026-04-18

## Why this exists

Owlvex uses both local analysis and AI-assisted review.

Customers need a clear answer to three questions:

- what stays local
- what is sent to the selected AI provider
- what is sent to Owlvex backend

This note is the current customer-facing boundary statement for demo, trial, and production-style use.

## Core boundary

Owlvex is designed around this split:

- deterministic scanning runs locally in the extension
- source code for AI-backed review is sent directly to the customer-selected model provider
- Owlvex backend acts as a control plane for licensing, prompt metadata, pack delivery, and scan/comparison metadata

Owlvex backend is not supposed to be the primary place where customer source code is sent for scanning.

## What stays local

The following stays on the user machine by default:

- deterministic rule execution
- local file content for deterministic scanning
- fix preview generation before the user chooses `Keep fix`
- local diff review before code is written
- project-context file loading
- provider secrets stored in VS Code secret storage
- licence secrets stored in VS Code secret storage

## What is sent to the selected AI provider

For AI-backed scanning and review, Owlvex can send:

- source code under review
- selected local context needed for the scan
- project-context contract text when the user has configured project context and AI review needs it
- grounded framework context
- grounded remediation context
- AI review prompts for:
  - finder
  - verifier
  - skeptic

This provider is chosen and configured by the user.

## What is sent to Owlvex backend

Owlvex backend is used as a control plane.

It can receive:

- licence validation requests
- prompt-build metadata such as:
  - frameworks
  - language
  - model
  - severity threshold
- scan-record metadata such as:
  - file name
  - file hash
  - language
  - provider
  - model
  - frameworks
  - score
  - finding counts and summaries
  - prompt id
- scan comparison metadata
- pack manifest and pack artifact requests

## What is not supposed to reach Owlvex backend

The intended boundary is that the following do not reach Owlvex backend during normal scan workflows:

- raw source code for scanning
- local project-context contract text as normal backend prompt input
- full assembled prompt snapshots for routine scan recording

## Trial and demo users

Trial and demo users follow the same data-boundary model.

If a trial user connects the extension to:

- an Owlvex backend URL
- a valid licence
- a selected AI provider

the backend should still remain on the metadata/control-plane side of the workflow rather than becoming a general source-code sink.

## Trial setup checklist

For a normal trial or demo setup, the user should configure:

- an Owlvex backend URL
- a valid licence
- a selected AI provider

That setup should not change the core boundary:

- deterministic scanning remains local
- AI source-code review still goes to the selected provider
- Owlvex backend remains on the control-plane and metadata side of the workflow

## Backend storage posture

Owlvex backend is expected to store operational and licensing data such as:

- licence records
- scan metadata
- comparison metadata
- prompt identifiers
- pack and policy metadata

It is not intended to become the default storage location for raw source code used in scans.

## Confidence and reasoning

Owlvex keeps deterministic proof separate from AI-backed reasoning.

- deterministic findings are explained through local rule proof and code evidence
- AI-backed findings can include a reasoning trail from:
  - finder
  - verifier
  - skeptic

That reasoning trail is for AI-reviewed findings only.

## Current operational note

This boundary statement reflects the current product direction and current codebase as of 2026-04-18.

It should be updated whenever:

- scan payload contracts change
- backend route scope changes
- trial onboarding changes what data can leave the extension
- provider or prompt flow changes widen or narrow the trust boundary
