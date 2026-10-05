#!/usr/bin/env python3
"""LIFE-48: Inventory service accounts and API integrations.

Default (offline) mode scans the inventory contract and emits a checklist
CSV proving every non-human credential is accounted for:

  * Okta API tokens (inventory "apiTokens")
  * OAuth/OIDC service apps (inventory "oauthApps")
  * service-account users (userType SERVICE or login starting with svc_)

Each item gets a migration note; the checklist ends with a coverage summary
so nothing slips through unaccounted.

CSV columns:
    kind, id, name, detail, created, last_updated, expires_at,
    migration_note, status

Examples:
    python3 inventory_service_accounts.py
    python3 inventory_service_accounts.py -o service-accounts.csv
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import load_inventory  # noqa: E402
from secure_io import csv_writer  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

HEADERS = ["kind", "id", "name", "detail", "created", "last_updated",
           "expires_at", "migration_note", "status"]


def is_service_account(user: dict) -> bool:
    return user.get("userType") == "SERVICE" or \
        (user.get("login") or "").lower().startswith("svc_")


def collect(inv: dict) -> list[dict]:
    rows = []
    for t in inv.get("apiTokens", []):
        rows.append({
            "kind": "api_token",
            "id": t.get("id"),
            "name": t.get("name") or t.get("clientName") or "",
            "detail": f"client: {t.get('clientName', '?')}",
            "created": t.get("created") or "",
            "last_updated": t.get("lastUpdated") or "",
            "expires_at": t.get("expiresAt") or "no expiry set",
            "migration_note": "Rotate into Entra: replace with a managed "
                              "identity or an Entra app registration client "
                              "secret; revoke the Okta token only after the "
                              "consumer is verified on the new credential.",
            "status": "pending",
        })
    for a in inv.get("oauthApps", []):
        rows.append({
            "kind": "oauth_service_app",
            "id": a.get("id"),
            "name": a.get("label") or a.get("name") or "",
            "detail": f"client_id={a.get('clientId', '?')}; "
                      f"grants={','.join(a.get('grantTypes', [])) or '?'}",
            "created": "",
            "last_updated": "",
            "expires_at": "",
            "migration_note": "Re-register as Entra app registration with "
                              "application permissions; re-consent admin "
                              "consent; update the service's token endpoint "
                              "to login.microsoftonline.com.",
            "status": "pending",
        })
    for u in inv.get("users", []):
        if not is_service_account(u):
            continue
        rows.append({
            "kind": "service_user",
            "id": u.get("id"),
            "name": u.get("login") or "",
            "detail": f"status={u.get('status')}; "
                      f"groups={','.join(u.get('groups', []))}",
            "created": "",
            "last_updated": "",
            "expires_at": "",
            "migration_note": "Replace with Entra managed identity if the "
                              "workload runs in Azure, else an Entra service "
                              "principal; move group memberships to the new "
                              "identity and disable (do not delete) the Okta "
                              "account until the consumer is verified.",
            "status": "pending",
        })
    return rows


def coverage_check(inv: dict, rows: list[dict]) -> list[str]:
    """Cross-check that the export left nothing unaccounted for."""
    problems = []
    # Every oauthApp id must be a real app in the inventory.
    app_ids = {a["id"] for a in inv.get("apps", [])}
    for r in rows:
        if r["kind"] == "oauth_service_app" and r["id"] not in app_ids:
            problems.append(f"oauth app {r['id']} has no matching app entry")
    # Every token's userId should resolve to a (service) user if present.
    user_ids = {u["id"] for u in inv.get("users", [])}
    for t in inv.get("apiTokens", []):
        uid = t.get("userId")
        if uid and uid not in user_ids:
            problems.append(f"api token {t.get('id')} owned by unknown "
                            f"user {uid}")
    # Apps with client credentials but no oauthApps entry are suspicious.
    oauth_ids = {r["id"] for r in rows if r["kind"] == "oauth_service_app"}
    for a in inv.get("apps", []):
        if a.get("signOnMode") == "OPENID_CONNECT" and a["id"] not in oauth_ids:
            problems.append(f"app {a.get('label')} is OIDC but missing from "
                            f"oauthApps export -- re-run the export")
    return problems


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Checklist every API token, OAuth service app and "
                    "service-account user in the Okta inventory, with "
                    "migration notes.")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("-o", "--output",
                   help="write checklist CSV here (default: stdout)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    inv = load_inventory(args.inventory)
    rows = collect(inv)

    with csv_writer(args.output, HEADERS) as w:
        w.writeheader()
        w.writerows(rows)

    problems = coverage_check(inv, rows)
    if not args.quiet:
        kinds = {}
        for r in rows:
            kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        print(f"{len(rows)} items inventoried: " +
              ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
        if problems:
            print("coverage problems:")
            for pr in problems:
                print(f"  !! {pr}")
        else:
            print("coverage: nothing unaccounted for")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
