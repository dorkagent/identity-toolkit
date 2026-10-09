# Okta → Microsoft Entra ID migration kit

A set of Python scripts for moving an organisation from Okta to Microsoft
Entra ID. One script exports the Okta org into a JSON inventory; the others
read that inventory to match and create users, rebuild groups, and produce
the paperwork app owners need to switch their apps over.

Everything runs offline against the bundled fixtures by default. Nothing
touches a live tenant unless you pass `--live`, and nothing is written to
Entra unless you also pass `--apply`.

## Where it stands

- **Okta export:** the live, read-only export has been run against a small
  Okta lab org. It has not met a large production org yet.
- **Entra writes:** `import_users.py --apply` and `mirror_groups.py --apply`
  have **not been run against a real Entra tenant**. They are tested against
  an in-memory imitation of the Graph endpoints they call (see Tests),
  built from the Microsoft Graph v1.0 docs. Try them in a lab tenant first.
- **Apps are plan only.** The kit does not create enterprise apps or app
  assignments in Entra.

## What each script does

| Script | What it does | Live access |
|---|---|---|
| `export_inventory.py` | Exports users (DEPROVISIONED included), groups and memberships, group rules, apps with SAML/OIDC settings and assignments (direct vs group), policies of every type the org has, and API tokens. Saves progress as it goes and can resume. | Okta, read only |
| `import_users.py` | Matches Okta users to Entra users by UPN, flags anything ambiguous, and creates the rest. Can issue Temporary Access Passes. | Graph read; writes with `--apply` |
| `mirror_groups.py` | Plans each Okta group as a dynamic, static or skipped Entra group, translating Okta group rules where it safely can. Creates the groups and writes static members. | Graph read; writes with `--apply` |
| `migrate_apps.py` | Writes a CSV for app owners: the SP values from Okta, the Entra values that replace Okta's, owner, and cutover notes per sign-on mode. | None |
| `inventory_service_accounts.py` | Lists API tokens, OIDC clients and service-account users, each with a note on where it should end up. | None |
| `cutover_tracker.py` | A small CSV tracker for each app's cutover status. | None |
| `verify_immutable_ids.py` | Checks that Entra users' `onPremisesImmutableId` matches the AD source anchor before you turn on sync. | Graph, read only |

### Users

`import_users.py` creates a user only when nothing about it is in doubt.
It flags, and leaves alone:

- DEPROVISIONED users, AD/LDAP-mastered users (those should come through
  Entra Connect or Cloud Sync), and service accounts;
- UPNs Entra won't accept, such as ones with `+` or accented characters;
- Okta users that share a login or an email, and Okta users whose email
  matches more than one Entra user;
- UPN matches whose names or email differ, and email-only matches
  (possible renames);
- users in an unverified domain, or in a federated domain when there's no
  source anchor to set `onPremisesImmutableId` from
  (`--federated-anchor-attr`).

Okta status sets the account state. ACTIVE, LOCKED_OUT, PASSWORD_EXPIRED
and RECOVERY users are created enabled; STAGED, PROVISIONED and SUSPENDED
users are created disabled and get no Temporary Access Pass
(`--skip-inactive` flags them instead). `usageLocation` comes from the Okta
`countryCode`, then `--usage-location`; users with neither are created
without one and listed, since licences can't be assigned until it's set.

The `mailNickname` is cleaned to characters Entra accepts. City, state,
street, postcode, company, employee id and mobile are copied over so that
translated group rules have something to match.

### Groups

For each Okta group, `mirror_groups.py` decides:

- **dynamic** when every active rule targeting the group translates, no
  rule excludes specific users or groups, and every current member is
  explained by the rules. Several rules are OR-ed together.
- **static** otherwise. Current members are copied in. If rules were
  involved, the plan adds a manual item saying the membership is now a
  snapshot.
- **skip** for Okta built-in groups (Everyone, Okta Administrators) and for
  groups imported from a directory or app.

The rule translator (`lib/rule_translator.py`) handles `==`, `!=`, `AND`,
`OR`, `!`, `String.stringContains` and `String.startsWith` on Okta profile
attributes that map to a user property Microsoft documents for dynamic
rules. It writes `-and`, `-or`, `-not`, escapes quotes with a backtick, and
checks the 3,072-character limit. `matches`, `Arrays.contains`,
`isMemberOf*`, `getInternalProperty`, numeric comparisons and attributes
such as `costCenter`, `division` and `employeeType` are listed for a person
to rewrite. Entra compares strings case-insensitively and Okta doesn't;
the plan points that out for each translated rule.

Dynamic groups need an Entra ID P1 licence for each member.

### Apps

`migrate_apps.py` takes SP values from the Okta app's SAML settings
(`audience`, `ssoAcsUrl`, NameID format and template, `idpIssuer` when
set) and gives the admin-API path to the app's Okta metadata. Entra
values are built from the tenant GUID (`--tenant`); the per-app metadata
URL needs the Entra application id once the enterprise app exists. Okta has
no app-owner field, so owners come from a CSV you supply (`--owners`); rows
without one say `MISSING`. Cells that would start a spreadsheet formula are
escaped.

## Safety rails

- Dry run unless `--apply`; `--apply` requires `--live`.
- `--apply` requires `--expect-tenant <tenant GUID>`. The run stops if the
  Graph credentials in your environment belong to any other tenant. This
  is the check that matters: `/organization` always agrees with the tenant
  the token was minted for, so comparing those two alone proves little.
- The Okta export checks that the token's org matches `OKTA_DOMAIN` (any
  Okta cell), or `OKTA_EXPECT_ORG_ID` for custom URL domains.
- You type `APPLY` to confirm, unless `--yes`. Without a terminal and
  without `--yes`, the script refuses.
- Resume journals are tied to the script, the Entra tenant id and the Okta
  org. A journal from another tenant, or an old journal with no binding,
  is refused rather than trusted.
- Every write goes to an append-only audit log (who, what, when, which
  tenant). Reports, plans, journals and checkpoints are written atomically
  with 0600 permissions, and secret-looking keys are scrubbed from reports.
- Temporary Access Passes go only where you ask: `--tap-file` (0600) or
  `--show-taps`. `--apply` won't start without one of those or `--no-tap`.
  A failed TAP is retried on the next run without touching the user.
- Group creation requires `--owner-id`. Learn warns that a group created
  with only `Group.Create` and no owner can't be modified afterwards.

## What doesn't move

Passwords and MFA enrolments (users re-register; the TAP gets them in),
policies (exported for reference; Conditional Access is designed by hand),
app SSO configuration and app assignments (planned, not created),
provisioning connectors, network zones, identity providers, authorization
servers, hooks and admin roles. Microsoft's Okta migration guides cover
the manual steps.

## Credentials and permissions

Read from environment variables only:

- Okta: `OKTA_DOMAIN`, `OKTA_API_TOKEN` (SSWS), optional
  `OKTA_EXPECT_ORG_ID`. Use a token from an admin with a read-only role.
  Okta recommends scoped OAuth service apps over SSWS tokens; support for
  that isn't built yet.
- Graph: `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`.

Graph application permissions, by script (check each against the
"Permissions" table on its Learn API page before granting):

| Script | Permissions |
|---|---|
| all `--live` | `Organization.Read.All` (tenant check) |
| `import_users.py` | `User.Read.All`, `Domain.Read.All`; with `--apply`: `User.Create`, plus a TAP permission for TAPs (`UserAuthMethod-TAP.ReadWrite.All` or the broader `UserAuthenticationMethod.ReadWrite.All`; Learn's table for that call is muddled, so test in a lab) |
| `mirror_groups.py --apply` | `Group.Read.All`, `User.Read.All`, `Group.Create`, `GroupMember.ReadWrite.All` |
| `verify_immutable_ids.py --live` | `User.Read.All` |

## Running it

```bash
cd okta-entra-migration
pip install -r requirements.txt

# Offline, against the fixtures
python3 export_inventory.py -o /tmp/inv.json
python3 import_users.py --inventory /tmp/inv.json
python3 mirror_groups.py --inventory /tmp/inv.json -o /tmp/group-plan.json
python3 migrate_apps.py --inventory /tmp/inv.json --tenant <tenant-guid>
python3 inventory_service_accounts.py --inventory /tmp/inv.json
python3 cutover_tracker.py --inventory /tmp/inv.json --report
python3 verify_immutable_ids.py --inventory /tmp/inv.json   # exits 1: one finding

# Live
python3 export_inventory.py --live -o inv.json            # add --resume after an interruption
python3 import_users.py --inventory inv.json --live --usage-location GB
python3 import_users.py --inventory inv.json --live --apply \
    --expect-tenant <tenant-guid> --tap-file taps.tsv
python3 mirror_groups.py --inventory inv.json --live --apply \
    --expect-tenant <tenant-guid> --owner-id <object-id>
```

The inventory format is described in `lib/inventory.py`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest          # or: python3 -m unittest discover -s tests
ruff check .
```

141 tests, no network. Besides unit tests for the helpers, they run the
real `OktaClient` and `GraphClient` against in-memory fakes of the Okta and
Graph endpoints (`tests/fakes.py`): paging, 401/403/429 handling, the
export checkpoint and resume, user and group `--apply` runs, member
batching, TAP retries, and journals from the wrong tenant. The translator
has a table of Okta rules and the Entra rule each should produce. CI runs
ruff and pytest on Python 3.10 and 3.12.

## Known gaps

- No `$batch` for member writes yet; members go in PATCH calls of 20.
- Policies are exported but not mapped to Conditional Access drafts.
- Authorization servers, network zones, IdPs, authenticators, hooks and
  admin roles aren't exported.
- App SAML metadata and signing certificates aren't downloaded; the CSV
  gives the path to fetch them.
- Retries cover 429 and 5xx on reads. A create that times out isn't
  retried; rerun and the journal or a UPN match picks it up.
