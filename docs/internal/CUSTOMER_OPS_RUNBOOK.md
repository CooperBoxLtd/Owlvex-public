# Customer Ops Runbook

Use this runbook for early customer support before marketplace and payment automation exist.

## Purpose

Provide a fast way to inspect:
- customers
- pending registrations
- issued licences
- verification state

and perform support actions without manual database browsing.

## Required environment

Set:

- `OWLVEX_ADMIN_KEY`
- optional `OWLVEX_API_URL`

Default API URL for the helper script is the dev backend:

- `https://owlvexdev-api.azurewebsites.net`

## Browser app

Primary ops surface:

- `https://owlvexdev-api.azurewebsites.net/v1/admin/app`
- `https://owlvex-api.azurewebsites.net/v1/admin/app`

The app supports:

- environment switch between `dev` and `prod`
- customer search and overview
- full JSON export
- resend verification
- revoke licences
- rotate licences
- ban / unban customer
- delete licence
- delete customer and related licence/scan/usage/comparison data

All actions still require `X-Admin-Key`; the page only provides the UI.
The environment selector changes which backend database the app reads and writes.

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

The CLI remains useful for scripted or terminal-only operations, but the browser app should be the default day-to-day admin surface.

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
- If a customer must be fully blocked:
  - ban the customer
  - this clears pending verification and deactivates active licences
- If data must be removed:
  - delete the specific licence, or delete the full customer tree

## Safety

- Treat the admin key like production infrastructure access.
- Prefer read-only lookup first, then resend, then rotate/deactivate only when needed.
- Use prod endpoints only for real customer support; do normal testing on dev.

## Deployment note

For current engineering operations on the Windows ARM development machine:

- build backend images locally with `docker buildx --platform linux/amd64`
- push those images to ACR
- deploy App Service from the pushed ACR tag

Do not assume a failed local build is automatically an ARM limitation.

Check Docker Desktop first:

```bash
docker version
docker buildx ls
```
