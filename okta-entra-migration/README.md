# Okta → Entra Migration Toolkit

Free, offline-first toolkit: export a complete Okta tenant inventory and
plan the move to Microsoft Entra ID. Local files only — nothing is
published.

**What this is, honestly:** a discovery and planning accelerator with two
carefully guarded live-mutation paths (user import, group mirroring). It
is **not** a production migration engine: the `--apply` paths have unit
tests and fixture-driven checks, but have **never been run against a live
tenant**. Treat them as reviewed-but-unproven until a lab tenant says
otherwise. Applications are plan-only by design — this toolkit does not
create Entra enterprise apps.

## Capability & maturity

| Script | Mode | Live behavior | Tested |
|---|---|---|---|
| `export_inventory.py` | Read | `--live` pages the Okta tenant (read-only) | Offline fixtures only |
| `import_users.py` | Plan + guarded apply | `--apply` creates Entra users + Temporary Access Passes | Unit + fixture tests; **no live tenant run** |
| `mirror_groups.py` | Plan + guarded apply | `--apply` creates Entra groups | Unit + fixture tests; **no live tenant run** |
| `migrate_apps.py` | **Plan only** | Never touches Entra; emits the IdP/SP mapping CSV for app owners | Offline fixtures only |
| `inventory_service_accounts.py` | **Report only** | No API writes at all | Offline fixtures only |
| `cutover_tracker.py` | **Local tracker** | CSV on disk; no API calls | Offline fixtures only |
| `verify_immutable_ids.py` | **Read-only check** | `--live` reads Entra users (no writes) | Unit + fixture tests; **no live tenant run** |

Every `--live` run prints the connected tenant/org and aborts on mismatch.
Every `--apply` asks for confirmation (type `APPLY`) unless `--yes`, keeps
a checkpoint journal for resume, and appends to an audit log
(`toolkit.audit.jsonl`): who did what, when, against which tenant — never
secret values.

## Layout

| Script | Card | What it does |
|---|---|---|
| `export_inventory.py` | LIFE-40 | Okta → shared JSON contract (users, groups, apps, policies, API tokens, OAuth apps). Pages large tenants. Read-only, even live. |
| `import_users.py` | LIFE-41 | Tiered match (UPN, then email) against Entra. Dry run by default; conflicts/duplicates/AD-mastered users are flagged for human review, never blind-imported. Guarded `--apply` creates users + Temporary Access Passes. |
| `mirror_groups.py` | LIFE-42 | Group recreation plans; translates Okta dynamic rules to Entra dynamic-membership syntax. Untranslatable rules are flagged for manual rewrite, never silently dropped. Guarded `--apply` creates groups (id-stamped; name collisions flagged, never auto-created). |
| `migrate_apps.py` | LIFE-43 | **Plan only** — per-app export + the IdP/SP mapping-table CSV (old Okta IdP values → new Entra IdP values) as the app-owner handoff artifact. Never creates Entra apps. |
| `inventory_service_accounts.py` | LIFE-48 | **Report only** — checklist of API tokens, OAuth service apps, and service-account users, each with a migration note; coverage check proves nothing is unaccounted for. |
| `cutover_tracker.py` | LIFE-44 | **Local tracker** — per-app cutover tracker CSV (pending → notified → updated → verified / rolled-back) plus an outstanding-items report. No API calls. |
| `verify_immutable_ids.py` | LIFE-50 | **Read-only check** — computes the expected Entra ImmutableID from each AD-mastered user's source anchor and compares it with Entra's `onPremisesImmutableId`, so sync hard-matches instead of duplicating. GUID anchors only; never writes. |
| `lib/okta_api.py` | — | Shared Okta client: cursor pagination, `x-rate-limit-reset` handling, SSWS auth from env. |
| `lib/graph_api.py` | — | Shared Microsoft Graph client: client-credentials from env, `@odata.nextLink` paging, Retry-After handling. |
| `lib/inventory.py` | — | Load/save helpers for the JSON contract. |
| `fixtures/` | — | Committed sample data proving the offline smoke tests pass. |

## Offline-first, always

Every script runs fully offline by default against the committed fixtures —
no credentials, no network. Live API calls only happen behind explicit
`--live` flags, with tokens read from environment variables (never
hardcoded, never prompted):

- Okta: `OKTA_DOMAIN` + `OKTA_API_TOKEN` (SSWS token, minted in the Okta
  Admin Console under Security > API > Tokens from an admin account with a
  read-only admin role). OAuth client-credentials is not supported: Okta's
  Org Authorization Server requires `private_key_jwt` for service apps, so
  this toolkit stays SSWS-only by design.
- Graph/Entra: `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`.

Write operations in Entra need a second explicit flag (`--apply`); dry run
stays the default even in live mode.

> Hard constraint, baked in: this toolkit never touches the Okta admin
> console and performs no interactive login. If the tenant is unreachable,
> work from an export taken earlier (or the fixtures) — the whole pipeline
> is designed to run from the JSON contract alone.

## The shared JSON contract

`export_inventory.py` writes `okta-inventory.json`; every other script reads
it. Shape:

```json
{
  "exportedAt": "2026-09-29T00:00:00Z",
  "source": {"live": false, "oktaDomain": "https://example.okta.com"},
  "users": [
    {"id": "00u…", "login": "ada@example.com", "email": "…",
     "firstName": "Ada", "lastName": "Lovelace", "status": "ACTIVE",
     "userType": "USER", "credentialProvider": "OKTA",
     "department": "Engineering", "title": "Staff Engineer",
     "manager": "grace@example.com",
     "groups": ["00g…"], "apps": ["0oa…"], "profile": {}}
  ],
  "groups": [
    {"id": "00g…", "name": "Engineering", "description": "…",
     "type": "OKTA_GROUP",
     "members": ["00u…"], "assignedApps": ["0oa…"],
     "dynamicRule": "user.department == \"Engineering\"",
     "dynamicRuleStatus": "ACTIVE"}
  ],
  "apps": [
    {"id": "0oa…", "name": "slack", "label": "Slack",
     "status": "ACTIVE", "signOnMode": "SAML_2_0",
     "sso": {"issuer": "http://www.okta.com/…", "ssoUrl": "…",
             "audience": "https://slack.com",
             "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
     "assignedGroups": ["00g…"], "assignedUsers": ["00u…"], "owner": ""}
  ],
  "policies": [
    {"id": "00p…", "name": "Default Policy", "type": "OKTA_SIGN_ON",
     "status": "ACTIVE",
     "rules": [{"id": "0pr…", "name": "Allow MFA", "status": "ACTIVE",
                "conditions": {}}]}
  ],
  "apiTokens": [
    {"id": "00T…", "name": "ci-deploy", "clientName": "CI Pipeline",
     "userId": "00u…", "created": "…", "lastUpdated": "…", "expiresAt": null}
  ],
  "oauthApps": [
    {"id": "0oa…", "name": "oidc_client", "label": "Report Bot",
     "status": "ACTIVE", "clientId": "0oab…",
     "grantTypes": ["client_credentials"], "redirectUris": [], "scopes": []}
  ]
}
```

Conventions: `users[].groups` / `users[].apps` are derived reverse indexes
of group memberships and app assignments; service-account users are regular
`users` entries with `userType == "SERVICE"` or a `svc_` login prefix.
`users[].credentialProvider` records the Okta credential provider type
(`OKTA`, `ACTIVE_DIRECTORY`, `LDAP`, …) — AD/LDAP-mastered users are never
created as Entra cloud duplicates. `apiTokens[].expiresAt` is `null` when
the token never expires (common — rotate these first).

## Required Okta token permissions

The toolkit is SSWS-only, so permissions come from the **admin role** of
the account that mints `OKTA_API_TOKEN` — not from OAuth scopes. Mint the
token from an account holding the **Read-Only Administrator** role (least
privilege); it covers every endpoint the export pages (users, groups and
memberships, apps and assignments, policies and rules, API tokens).

For Entra writes the app registration needs Microsoft Graph **application**
permissions such as `User.ReadWrite.All`, `Group.ReadWrite.All`,
`Application.ReadWrite.All` (least privilege per script; reads only need
the `.Read.All` variants). Creating Temporary Access Passes additionally
needs `UserAuthenticationMethod.ReadWrite.All`.

## Tests

Unit + contract tests (stdlib only, no network — run in under a second):

```bash
cd ~/workspace/okta-entra-toolkit
python3 -m unittest discover -s tests
```

They pin the inventory contract, the matching tiers and identity guards,
the group id-ledger, the journal/audit resume semantics, the tenant
verification, the rate-limit math, and the secret-scrubbing/0600 output
handling. If a test fails after a code change, the change broke a promise
— update the promise deliberately, not the test reflexively.

## Smoke tests (offline)

```bash
cd ~/workspace/okta-entra-toolkit
python3 export_inventory.py -o /tmp/inv.json
python3 import_users.py --inventory /tmp/inv.json
python3 mirror_groups.py --inventory /tmp/inv.json
python3 migrate_apps.py --inventory /tmp/inv.json --tenant TENANT_ID
python3 inventory_service_accounts.py --inventory /tmp/inv.json
python3 cutover_tracker.py --inventory /tmp/inv.json --report
```

All six pass against the committed fixtures (`fixtures/okta-raw.sample.json`
→ `fixtures/okta-inventory.sample.json`, `fixtures/entra-tenant.sample.json`).
Only dependency beyond the stdlib: `requests`.
