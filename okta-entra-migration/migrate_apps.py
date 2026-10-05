#!/usr/bin/env python3
"""LIFE-43: Migrate applications and build the IdP/SP mapping table.

Default (offline) mode reads the inventory contract and emits the app-owner
handoff artifact: a CSV mapping table with one row per app carrying the
old Okta IdP values and the new Entra IdP values side by side, plus a
recreation plan JSON (sign-on mode, group assignments, owner notes).

Entra IdP values are *template* values for a given tenant -- the operator
fills in GRAPH_TENANT_ID (or passes --tenant) and confirms them after the
Entra enterprise app is created; they are clearly marked as such.

CSV columns:
    app_name, sign_on_mode, okta_issuer, okta_sso_url, okta_audience,
    okta_sp_url, entra_issuer, entra_sso_url, entra_audience,
    assigned_groups, assigned_users, owner, cutover_notes

Examples:
    python3 migrate_apps.py                                   # to stdout
    python3 migrate_apps.py -o mapping.csv --plan plan.json
    python3 migrate_apps.py --tenant contoso.onmicrosoft.com
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import load_inventory, by_id  # noqa: E402
from secure_io import csv_writer, write_json  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

HEADERS = ["app_name", "sign_on_mode", "okta_issuer", "okta_sso_url",
           "okta_audience", "okta_sp_url", "entra_issuer", "entra_sso_url",
           "entra_audience", "assigned_groups", "assigned_users", "owner",
           "cutover_notes"]

# Per-sign-on-mode handoff guidance.
MODE_NOTES = {
    "SAML_2_0": "Recreate as Entra SAML enterprise app; upload SP metadata; "
                "swap IdP SSO URL + entity ID + signing cert in the SP. "
                "Test with one pilot user before cutover.",
    "OIDC": "Register app in Entra (App registrations); update client_id / "
            "authority / redirect URIs in the SP. Client secret rotation "
            "required -- do not reuse Okta secret.",
    "OPENID_CONNECT": "Recreate OAuth client in Entra; grant types must be "
                      "re-authorized. Service principals: see "
                      "inventory_service_accounts.py.",
    "BOOKMARK": "Bookmark/portal link -- no SSO to migrate; re-point users "
                "to the Entra My Apps portal entry.",
    "BROWSER_PLUGIN": "SWA plugin app -- no Entra equivalent; re-evaluate: "
                      "SAML/OIDC or password SSO via Entra.",
}


def entra_templates(tenant: str) -> dict:
    """Template Entra IdP values; operator must confirm post-creation."""
    return {
        "issuer": f"https://sts.windows.net/{tenant}/",
        "sso_url": f"https://login.microsoftonline.com/{tenant}/saml2",
        "note": "TEMPLATE -- confirm after creating the Entra enterprise app",
    }


def build_rows(inv: dict, tenant: str) -> list[dict]:
    groups = by_id(inv["groups"])
    users = by_id(inv["users"])
    tmpl = entra_templates(tenant)
    rows = []
    for a in inv["apps"]:
        sso = a.get("sso", {}) or {}
        mode = a.get("signOnMode", "")
        note = MODE_NOTES.get(mode, "Sign-on mode needs manual review.")
        if mode == "SAML_2_0":
            note += " " + tmpl["note"]
        row = {
            "app_name": a.get("label") or a.get("name"),
            "sign_on_mode": mode,
            "okta_issuer": sso.get("issuer", ""),
            "okta_sso_url": sso.get("ssoUrl", ""),
            "okta_audience": sso.get("audience", ""),
            "okta_sp_url": sso.get("url", ""),
            "entra_issuer": tmpl["issuer"] if mode == "SAML_2_0" else "",
            "entra_sso_url": tmpl["sso_url"] if mode == "SAML_2_0" else "",
            "entra_audience": "",
            "assigned_groups": ";".join(
                groups[g]["name"] for g in a.get("assignedGroups", [])
                if g in groups),
            "assigned_users": ";".join(
                users[u]["login"] for u in a.get("assignedUsers", [])
                if u in users and users[u].get("login")),
            "owner": a.get("owner") or "",
            "cutover_notes": note,
        }
        rows.append(row)
    return rows


def build_plan(inv: dict, tenant: str) -> dict:
    """Machine-readable recreation plan (feeds cutover_tracker.py)."""
    groups = by_id(inv["groups"])
    plan = {"tenant": tenant, "apps": []}
    for a in inv["apps"]:
        plan["apps"].append({
            "oktaAppId": a["id"],
            "name": a.get("label") or a.get("name"),
            "signOnMode": a.get("signOnMode"),
            "owner": a.get("owner") or "",
            "assignedGroups": [groups[g]["name"]
                               for g in a.get("assignedGroups", [])
                               if g in groups],
            "assignedUserCount": len(a.get("assignedUsers", [])),
        })
    return plan


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Emit the IdP/SP mapping-table CSV for the app-owner "
                    "handoff, plus a recreation plan.")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("--tenant", default="TENANT_ID",
                   help="Entra tenant id/domain used for template IdP values")
    p.add_argument("-o", "--output",
                   help="write mapping CSV here (default: stdout)")
    p.add_argument("--plan", help="write recreation plan JSON here")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    inv = load_inventory(args.inventory)
    rows = build_rows(inv, args.tenant)

    with csv_writer(args.output, HEADERS) as w:
        w.writeheader()
        w.writerows(rows)
    if args.output and args.output != "-":
        log(f"mapping table: {len(rows)} apps -> {args.output}")

    if args.plan:
        write_json(args.plan, build_plan(inv, args.tenant))
        log(f"recreation plan -> {args.plan}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
