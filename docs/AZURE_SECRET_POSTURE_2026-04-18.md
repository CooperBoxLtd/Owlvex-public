# Owlvex Azure Secret Posture Note

Date: 2026-04-18

## Purpose

This note records the current live Azure secret posture compared with the intended infrastructure model in the repo.

It exists so production and trial readiness discussions do not assume a stronger live posture than the one currently deployed.

## Intended posture

The repo infrastructure direction expects a stronger secret-management model built around:

- Azure App Service for the backend
- PostgreSQL for backend data
- Azure Key Vault for secret storage and secret delivery
- supporting operational resources such as logging/monitoring

That is the target model described by the infrastructure layer.

## Observed live posture

From the live Azure review already performed for the Owlvex production resource group:

- resource group: `owlvex-prd`
- region: `uksouth`

Observed live resources:

- Azure Container Registry
- Azure Database for PostgreSQL Flexible Server
- App Service Plan
- Linux Web App for Containers
- Azure OpenAI / Cognitive Services account

Observed live secret handling:

- important backend secrets are currently held in App Service application settings

Examples of secret-bearing settings observed by name:

- `DATABASE_URL`
- `SECRET_KEY`
- `ADMIN_KEY`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `RESEND_API_KEY`

## Drift summary

Current drift between intended and live posture:

- the intended model expects Key Vault involvement
- the live reviewed resource group did not show a Key Vault resource in place
- the live reviewed resource group also did not show the stronger monitoring resources expected by the infra direction

This does not automatically mean the live posture is unsafe.

It does mean:

- the live posture is weaker than the intended target model
- production-readiness wording should not overstate the current secret-management posture
- trial and demo onboarding should be evaluated against the real live posture, not only the intended future posture

## Working interpretation

Current live posture should be treated as:

- acceptable for ongoing controlled development and demo use if access is tightly managed
- not yet equivalent to the intended hardened production secret-management model

## Recommended next steps

1. Decide whether Key Vault alignment is required before broader external trial distribution.
2. Record any accepted temporary exception explicitly in production-readiness discussions.
3. Keep customer-facing security statements aligned with the real deployed posture.
4. Re-run this note after any Azure infrastructure changes so drift stays visible.
