# Billing Deferred Until Billable

Date: 2026-04-18

## Current decision

Owlvex is currently operating in a free-trial / demo phase.

For this phase:

- billing remains disabled by default
- trials do not depend on Stripe
- licences can still be issued for trial use

This is an intentional product decision, not an accidental gap.

## Why this document exists

The codebase already contains billing-related paths.

That can create confusion unless the current decision is explicit.

This note exists to say:

- billing code exists
- billing security risks have been reviewed
- billing is not part of the active trial path right now
- some billing-specific hardening is intentionally deferred until the product becomes billable

## What remains deferred

The main deferred billing security items are:

- webhook idempotency for repeated or replayed Stripe events
- stronger duplicate-prevention on Stripe-linked licence issuance
- full billing-path operational monitoring and verification
- billing-path release checks that only matter once Stripe is live

## What is still required now

Even while billing is deferred, the following still matter now:

- the backend remains metadata-only for scan workflows
- trial onboarding preserves the same source-code boundary
- licence handling remains secure
- backend secrets and logs do not leak sensitive material

## Reopen conditions

This deferred work should be reopened when any of the following becomes true:

- Stripe is scheduled for activation
- paid trials or subscriptions are introduced
- automated billing becomes part of the production launch path

## Rule

Billing should stay disabled until the product is intentionally moved into a billable phase and the deferred billing hardening items are scheduled and completed.
