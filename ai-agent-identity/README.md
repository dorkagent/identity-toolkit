# AI Agent Identity Governance

Report-only tooling for the identity problem enterprise AI agents create:
non-human credentials with human-scale power and nobody clearly owning them.
It scans the shared Okta inventory contract for the identities an AI-agent
deployment would touch (API tokens, OAuth service apps, service-account
users) and scores each one against a deterministic risk rubric, so the
risks the Oct 15 panel flagged (shipped code, AI-security, threat modeling)
show up as something you can run, not just something you can describe.

**What this is, honestly:** a discovery and prioritization aid for agentic
AI identity posture. It reads an inventory file and writes a Markdown risk
review. It is **not** a privileged access manager, **not** a secrets
rotator, and **not** a live monitor: it changes nothing in any tenant, it
holds no credentials, and its findings are only as fresh as the export you
feed it. Treat the report as a starting point for the remediation work, not
as proof the work is done.

## The lifecycle this serves

Enterprise AI agents need the same identity lifecycle humans get, and most
shops have never built it:

1. **Provision**: every agent gets a dedicated non-human identity. No
   shared tokens, no borrowing a human admin's API key for the demo that
   became production.
2. **Scope**: least privilege from day one. Short-lived credentials,
   narrow scopes, and no admin-role linkage unless someone signs for it.
3. **Monitor**: recurring review of what the agents hold. That is what
   `inventory_agent_identities.py` automates: the recurring "what do our
   non-human identities actually have" pass.
4. **Deprovision**: orphaned credentials get revoked, not rediscovered
   during the incident.

## Capability & maturity

| Script / doc | Mode | Live behavior | Tested |
|---|---|---|---|
| `inventory_agent_identities.py` | **Report only** | No API calls at all; reads the inventory JSON | Unit tests pin every rubric tier; fixture demo |
| `mcp_tool_review.md` | **Checklist + threat model** | Not code; a review procedure | Read-through only |
| `fixtures/agent-inventory.sample.json` | Sample data | N/A | Drives the demo |

The rubric is deliberately simple and deterministic: the highest matching
rule wins and every matched reason is printed, so a finding can be audited
without trusting a black box.

| Rule | Tier |
|---|---|
| API token owned by an admin-role-linked user | critical |
| API token never expires | high |
| API token orphaned (owner not in the user inventory) | high |
| OAuth service app with `client_credentials` + broad scopes | high |
| Service-account user holding an admin role | high |
| API token older than 365 days | medium |
| OAuth service app with `client_credentials`, narrow scopes | medium |
| Service-account user in human-like groups | medium |
| Service-account user dormant (non-ACTIVE status) | medium |
| None of the above | low |

## Layout

| File | What it does |
|---|---|
| `inventory_agent_identities.py` | Scores every non-human identity in the inventory and emits a Markdown risk review (stdout, or `-o` file). |
| `mcp_tool_review.md` | How to inventory MCP servers and tools, scope tool permissions, classify tool data, and a STRIDE-style threat model for enterprise AI-agent deployment. |
| `fixtures/agent-inventory.sample.json` | Committed sample inventory exercising every rubric tier, so the demo runs with no credentials and no network. |
| `tests/test_rubric.py` | Stdlib unittests pinning each tier against the fixture. |

## Offline-first, always

The script reads the same `okta-inventory.json` contract the migration
toolkit produces (`export_inventory.py` in `okta-entra-migration/`). Run
that export first, then point this script at the result:

```bash
python3 inventory_agent_identities.py --inventory /tmp/okta-inventory.json -o agent-risk.md
```

No `--live` flag exists on purpose: there is nothing to make live. Tokens
come from nowhere because none are needed.

```bash
# Demo against the fixture (no credentials, no network):
python3 inventory_agent_identities.py
python3 -m unittest discover -s tests
```

## Honesty notes

- The rubric is heuristic, not authoritative. "Broad scope" is a
  substring match on scope names; a scope named `admin:read` at your shop
  might be harmless and one named `reports:read` might be sensitive. Read
  the reasons column, not just the tier.
- Admin linkage is inferred from group names containing "admin". If your
  tenant names its admin groups differently, adjust `ADMIN_GROUP_HINTS`.
- MCP review doc is a procedure, not automation: someone still has to do
  the reading.
- Like the rest of this repo, nothing here has been run against a live
  tenant. The fixture proves the logic; your tenant proves the findings.
