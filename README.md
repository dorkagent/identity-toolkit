# Identity Toolkit

Practical, offline-first tooling for Okta administration and Okta → Microsoft Entra ID migration planning. Every script solves one concrete problem, and everything runs against local fixtures before it ever touches a live tenant.

## What's inside

### `okta-admin-scripts/` — day-to-day Okta automation
Standalone PowerShell + Python scripts for the problems IAM teams hit every week: MFA coverage audits, sign-on policy linting, stale-account sweeps, license optimization, break-glass monitoring, admin privilege reviews, JML automation, app rationalization, tenant drift detection, and System Log threat detections. Each script ships in both languages and shares one client module, so auth, pagination, and rate-limiting are solved once. See [its README](okta-admin-scripts/README.md).

### `okta-entra-migration/` — Okta → Entra migration planning toolkit
Offline-first scripts that export an Okta org into a JSON inventory and plan the move to Microsoft Entra ID. Covers user export/matching, group mirroring (including Okta dynamic-rule → Entra dynamic-membership translation), app-migration planning with an IdP/SP mapping handoff for app owners, service-account inventory, ImmutableID verification, and a per-app cutover tracker. See [its README](okta-entra-migration/README.md) for what each script does and how it has been tested.

## Honesty notes

- The migration kit's `--apply` paths are tested against mocked Graph endpoints but have **never been run against a live Entra tenant**. Try them in a lab tenant first.
- Applications are plan-only by design — the toolkit does not create Entra enterprise apps.
- Live runs print the connected tenant or org. Scripts that write to Entra need `--expect-tenant` and stop if the credentials belong to a different tenant. Tokens come from environment variables; nothing here hardcodes a secret or asks you to paste one into a file.

## About the author

_Identity section to be added — this repo is published ahead of the author's public profile._
