# okta-admin-scripts

Command-line scripts for routine Okta admin and audit work: who holds admin
roles and how, which accounts are dormant, whether a leaver's access is really
gone, how policies are set up. Most are read-only reports. Two can change
users (the stale-account sweeper and the JML kit), and both do nothing unless
you pass `--apply` / `-Apply`.

There is a Python set and a PowerShell set. Nine tools exist in both, one is
Python-only and seven are PowerShell-only; the table below says which.

## Status

- Tested with mocked HTTP: 73 pytest tests for the Python client and scripts,
  11 Pester tests for the PowerShell module. CI runs ruff, pytest,
  PSScriptAnalyzer and Pester on every change to this folder.
- Run read-only against a free Okta Integrator (Identity Engine) sandbox org
  with a handful of users. Every report script in both languages ran
  against it through a proxy that blocked anything but GET.
- The write paths (`--apply` / `-Apply`) have only been exercised against
  mocks, never against a real org.
- Not tested on Classic Engine orgs or on large tenants. Expect rate-limit
  waits on big orgs: several scripts make one call per user or per app.

Try anything that writes on a preview or sandbox org first.

## Setup

Python 3.11+ or PowerShell 7+.

```bash
pip install -r requirements.txt
export OKTA_DOMAIN=https://your-org.okta.com
```

Then pick one way to authenticate.

**OAuth service app (recommended by Okta).** Create an API Services app with
public key / private key client authentication, grant it the scopes the
scripts need (below), and point the scripts at the private key:

```bash
export OKTA_CLIENT_ID=0oa...
export OKTA_PRIVATE_KEY=/path/to/private-key.pem
export OKTA_SCOPES="okta.users.read okta.groups.read okta.apps.read okta.logs.read okta.roles.read okta.policies.read"
export OKTA_KEY_ID=...        # only if the app has more than one key
```

The scripts sign a short-lived `private_key_jwt` assertion and use the
client-credentials grant. DPoP-bound tokens aren't supported, so leave
"Require DPoP" off on the app. Both languages have been run this way against
a real Okta org (Oct 2026), including the JML and sweeper write paths, with a
service app holding a custom admin role scoped to a few groups.

**SSWS API token.** Simpler, but the token carries the full admin role of
whoever created it. For the reports, create it while signed in as a
Read-Only Admin.

```bash
export OKTA_API_TOKEN=00...
```

PowerShell reads the same variables (`$env:OKTA_DOMAIN = '...'` and so on).
If both an API token and OAuth settings are set, the API token is used.

Scopes by area: reading users and factors needs `okta.users.read`; groups
`okta.groups.read`; apps `okta.apps.read`; System Log `okta.logs.read`;
admin roles `okta.roles.read`; policies `okta.policies.read`; zones
`okta.networkZones.read`; authenticators `okta.authenticators.read`;
authorization servers `okta.authorizationServers.read`; API token metadata
`okta.apiTokens.read`. The two write scripts also need `okta.users.manage`,
and the JML kit `okta.groups.manage` and `okta.apps.manage`.

## Scripts

| Tool | Python | PowerShell | What it does | Changes Okta? |
|---|---|---|---|---|
| Admin privilege review | `admin_privilege_reviewer.py` | `Admin-PrivilegeReviewer.ps1` | Every admin-role holder, direct vs via group, custom roles, oldest grant, last System Log activity, MFA summary | No |
| Privilege paths | | `Get-PrivilegePath.ps1` | How each user holds admin rights: direct, via group, or via a group rule feeding that group | No |
| Leaver check | | `Confirm-LeaverDeprovisioned.ps1` | Per-user PASS/FAIL evidence that a leaver's status, sessions, apps, roles, factors, groups and API tokens are cleaned up | No |
| Stale accounts | `stale_account_sweeper.py` | `Stale-AccountSweeper.ps1` | Dormant and never-used accounts; can suspend (default) or deactivate them | With `--apply` |
| JML kit | `jml_automation_kit.py` | `JML-AutomationKit.ps1` | Joiner/mover/leaver changes from a CSV | With `--apply` |
| Sign-on policy lint | `sign_on_policy_linter.py` | `Sign-OnPolicyLinter.ps1` | Global session and app sign-in rules without MFA, one-factor rules, wide network zones | No |
| OIE posture | | `Test-OiePosture.ps1` | App sign-in rules, authenticators, enrollment policies, password policies and zones on Identity Engine | No |
| Group rule audit | | `Test-GroupRule.ps1` | Group rules that are invalid, point at missing or empty groups, or duplicate each other | No |
| API token owners | | `Find-OrphanedApiToken.ps1` | Each API token's owner, owner status and owner's admin roles (needs super admin) | No |
| Access review pack | | `New-AccessReviewPack.ps1` | One CSV per app of who has access, for a manager review | No |
| MFA coverage | `mfa_coverage.py` | | Active factors per user: none, phishable only, mixed, phishing-resistant only | No |
| Break-glass activity | `break_glass_monitor.py` | `Break-GlassMonitor.ps1` | Sign-in, MFA and Admin Console events for named emergency accounts; one-shot or polling | No |
| Threat detections | `system_log_threat_detections.py` | `SystemLog-ThreatDetections.ps1` | Impossible travel, push fatigue, MFA failures then success, one session from several IPs | No |
| License estimate | `license_optimizer.py` | `License-Optimizer.ps1` | Apps with assignments but no SSO sign-ins in the window, priced per seat | No |
| App rationalization | `app_rationalizer.py` | `App-Rationalizer.ps1` | Apps ranked by SSO use, with duplicate and unused flags | No |
| Config drift | `tenant_drift_detector.py` | `Tenant-DriftDetector.ps1` | Snapshot policies, zones, apps and admin roles; diff two snapshots | No |
| Restore plan | | `New-RestorePlan.ps1` | Offline, dependency-ordered restore plan from a JSON backup (nothing in this repo produces that backup yet) | No |

All scripts live in `scripts/`. Run a Python script with `--help`, or
`Get-Help ./scripts/<Name>.ps1 -Full` for PowerShell.

The two drift detectors write different snapshot formats; diff snapshots made
by the same one.

## Output

Python scripts print a text table by default. `--json` prints JSON instead.
`--output FILE` writes the same thing to a file (CSV when the name ends in
`.csv`). PowerShell scripts print a table, or JSON with `-Json`, and `-Output`
also writes a CSV or JSON file.

Report files are created readable only by you (Python, and PowerShell drift
snapshots on Linux/macOS), since they contain names, logins and tenant
configuration. CSV cells that start with `=`, `+`, `-` or `@` get a leading `'`
so a user-editable profile field can't run as a spreadsheet formula.

## How the write scripts protect you

`stale_account_sweeper.py` / `Stale-AccountSweeper.ps1`

- Report only unless `--apply`.
- Default action is suspend, which can be undone; deactivate is opt-in.
- Never touches the owner of the token running the script, owners of any
  active API token (Okta revokes a user's tokens when the user is
  deactivated), admin-role holders, anyone in `--exclude-file`, or members of
  `--exclude-group`.
- `--limit N` caps the number of changes; `--max N` (default 25) refuses to
  start if more accounts than that would change.
- One failed call is recorded and the run continues.

`jml_automation_kit.py` / `JML-AutomationKit.ps1`

- Report only unless `--apply`.
- New users are created in their OKTA_GROUP groups in the same call
  (`groupIds`). An admin whose role is scoped to groups can only create users
  that way; adding the groups afterwards gets HTTP 403 for them.
- Profile updates are partial (`POST /api/v1/users/{id}`), so attributes not
  in the CSV are left alone.
- `--prune` only removes OKTA_GROUP memberships and direct app assignments,
  never Everyone, AD/LDAP-imported groups or group-based app assignments, and
  skips any row whose groups or apps cell is empty.
- A failure on one row is recorded and the batch continues; bad credentials
  (HTTP 401) stop the run.

## System Log reads

Reports use bounded queries (`since` and `until`), which Okta pages to a
definite end. Watch modes poll and stop each pass at the first empty page.
Okta keeps 90 days of System Log, so longer lookbacks are cut to 90 days.

Rate limits: on HTTP 429 the client waits until the time in
`x-rate-limit-reset` (a Unix timestamp) and retries. 5xx and network errors
are retried with backoff.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest
```

```powershell
Install-Module PSScriptAnalyzer, Pester -Scope CurrentUser
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
Invoke-Pester ./tests
```

The Python tests use a small fake of the Okta API (`tests/conftest.py`), so
nothing talks to a real org.

## Known gaps

- PowerShell scripts have no Pester tests of their own yet; only the shared
  module is unit-tested. They were checked against a mock server and the
  sandbox org by hand.
- `Get-PrivilegePath.ps1` and the admin reviewers show custom roles by label
  but don't resolve their resource sets.
- `Confirm-LeaverDeprovisioned.ps1` doesn't yet check OAuth grants and refresh
  tokens, devices, or IdP links.
- `Test-GroupRule.ps1` doesn't check group IDs referenced inside rule
  expressions, and its ConflictingTargets flag also fires on the normal
  pattern of several rules feeding one group.
- The license estimate is app-level only. Apps that never emit
  `user.authentication.sso` look unused.
- On Identity Engine the factors API answers in the calling admin's policy
  context, so MFA results are a hint rather than an audit.
