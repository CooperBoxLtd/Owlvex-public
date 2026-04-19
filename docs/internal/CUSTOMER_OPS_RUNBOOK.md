# Customer Ops Runbook

Use this runbook for early customer support before marketplace and payment automation exist.

## Purpose

Provide a fast way to inspect:
- customers
- pending registrations
- issued licences
- verification state

and perform basic support actions without manual database browsing.

## Required environment

Set:

- `OWLVEX_ADMIN_KEY`
- optional `OWLVEX_API_URL`

Default API URL for the helper script is the dev backend:

- `https://owlvexdev-api.azurewebsites.net`

## Read-only lookup

Overview of recent customers:

```bash
node tools/admin-db-view.mjs overview
```

Lookup by email:

```bash
node tools/admin-db-view.mjs customer someone@example.com
```

## Support actions

Resend verification for a pending registration:

```bash
node tools/admin-db-view.mjs resend-verification someone@example.com
```

Deactivate active licence(s) for a customer:

```bash
node tools/admin-db-view.mjs deactivate someone@example.com
node tools/admin-db-view.mjs deactivate someone@example.com trial
```

Rotate a licence and issue a fresh key:

```bash
node tools/admin-db-view.mjs rotate someone@example.com
node tools/admin-db-view.mjs rotate someone@example.com developer
```

## Operational notes

- Free and Trial should only become active after email verification.
- If a user says they never received a code:
  - confirm the email exists
  - confirm whether verification is still pending
  - resend verification
- If a user lost access to a licence:
  - inspect the customer by email
  - rotate the licence if a fresh key is needed
- If a licence must be stopped quickly:
  - deactivate by email

## Safety

- Treat the admin key like production infrastructure access.
- Prefer read-only lookup first, then resend, then rotate/deactivate only when needed.
- Use prod endpoints only for real customer support; do normal testing on dev.
