#!/usr/bin/env python3
"""Build the app-owner handoff sheet for moving apps from Okta to Entra.

Plan only: nothing is created in Entra. Output is one CSV row per Okta app
with what the app owner (the service-provider side) needs to know, plus a
JSON plan that cutover_tracker.py can work from.

What's in a row and where it comes from:

* SP values from the Okta app's SAML settings (Okta API,
  SamlApplicationSettingsSignOn): ``audience`` (SP entity id),
  ``ssoAcsUrl``, NameID format and template, and ``idpIssuer`` when the
  app sets one. Okta's own IdP issuer and signing certificate live in the
  app's SAML metadata, so the row gives the admin-API path to fetch it
  (``/api/v1/apps/{id}/sso/saml/metadata``) rather than guessing.
* Entra values built from the tenant GUID (``--tenant``): identifier
  ``https://sts.windows.net/{tenant}/``, login URL
  ``https://login.microsoftonline.com/{tenant}/saml2``, and the per-app
  federation metadata URL, which needs the Entra application id once the
  enterprise app exists. Entra uses the tenant GUID here, not a domain.
* Owner from ``--owners`` (CSV with ``okta_app_id`` or ``app_name`` plus
  ``owner``). Okta has no app-owner field, so without that file every
  row says MISSING.
* Assigned users: direct assignments when the export recorded
  AppUser.scope, so owners aren't handed group-derived users twice.

Examples:
    python3 migrate_apps.py                                   # to stdout
    python3 migrate_apps.py --tenant <tenant-guid> --owners owners.csv \\
        -o mapping.csv --plan plan.json
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import by_id, load_inventory  # noqa: E402
from secure_io import csv_writer, write_json  # noqa: E402
from tenant_guard import is_guid  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

HEADERS = ["okta_app_id", "app_name", "sign_on_mode", "status", "owner",
           "sp_entity_id", "sp_acs_url", "name_id_format", "name_id_template",
           "okta_idp_issuer", "okta_metadata_path",
           "entra_identifier", "entra_login_url", "entra_metadata_url",
           "assigned_groups", "assigned_users_direct", "assigned_users_total",
           "cutover_notes"]

SAML_MODES = ("SAML_2_0", "SAML_1_1")

# Okta Application.signOnMode values (Okta Management OpenAPI spec).
MODE_NOTES = {
    "SAML_2_0": "Create an Entra enterprise app (gallery if one exists, else "
                "non-gallery SAML). Give the owner the Entra identifier, "
                "login URL and signing certificate from the metadata URL. "
                "Test with one pilot user before cutover; rollback is "
                "re-pointing the SP at Okta.",
    "SAML_1_1": "SAML 1.1: check the SP supports SAML 2.0 before moving; "
                "Entra enterprise apps issue SAML 2.0 tokens.",
    "OPENID_CONNECT": "Register the app in Entra (App registrations). The "
                      "owner updates client id, authority and redirect URIs; "
                      "issue a new secret or certificate, never reuse the "
                      "Okta one. Service clients: see "
                      "inventory_service_accounts.py.",
    "WS_FEDERATION": "WS-Federation. If this is the Microsoft 365 app, it is "
                     "the federation itself: plan the domain cutover "
                     "(staged rollout, then convert the domain to managed) "
                     "and switch off Okta's provisioning to Microsoft 365, "
                     "per Microsoft's Okta federation migration guide.",
    "BOOKMARK": "Link only, no SSO. Recreate as a My Apps link if users "
                "still need it.",
    "BROWSER_PLUGIN": "Okta browser-plugin (SWA) app. Credentials can't be "
                      "exported; move the app to SAML/OIDC if it supports "
                      "it, or to Entra password-based SSO.",
    "AUTO_LOGIN": "Okta auto-login (SWA) app. Credentials can't be exported; "
                  "move to SAML/OIDC or Entra password-based SSO.",
    "SECURE_PASSWORD_STORE": "Password-store app. Credentials can't be "
                             "exported; users re-enter them, or move the "
                             "app to federated SSO.",
    "BASIC_AUTH": "Basic-auth app. No federation to move; decide whether it "
                  "stays behind Entra password-based SSO or an app proxy.",
}


def entra_values(tenant: str) -> dict:
    """Entra SAML values for a tenant GUID, or placeholders when it isn't one."""
    t = tenant if is_guid(tenant) else "<tenant-guid>"
    return {
        "identifier": f"https://sts.windows.net/{t}/",
        "login_url": f"https://login.microsoftonline.com/{t}/saml2",
        "metadata_url": (f"https://login.microsoftonline.com/{t}/"
                         f"federationmetadata/2007-06/federationmetadata.xml"
                         f"?appid=<entra-application-id>"),
    }


def load_owners(path: str | None) -> dict[str, str]:
    """Owner lookup keyed by Okta app id and by lower-cased app name."""
    if not path:
        return {}
    owners: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            owner = (row.get("owner") or "").strip()
            if not owner:
                continue
            if row.get("okta_app_id"):
                owners[row["okta_app_id"].strip()] = owner
            if row.get("app_name"):
                owners["name:" + row["app_name"].strip().lower()] = owner
    return owners


def owner_for(app: dict, owners: dict[str, str]) -> str:
    name = (app.get("label") or app.get("name") or "").lower()
    return owners.get(app["id"]) or owners.get("name:" + name) \
        or app.get("owner") or ""


def build_rows(inv: dict, tenant: str, owners: dict | None = None) -> list[dict]:
    owners = owners or {}
    groups = by_id(inv["groups"])
    users = by_id(inv["users"])
    entra = entra_values(tenant)
    meta_base = (inv.get("source") or {}).get("oktaDomain") or ""
    rows = []
    for a in inv["apps"]:
        sso = a.get("sso", {}) or {}
        mode = a.get("signOnMode", "")
        saml = mode in SAML_MODES
        note = MODE_NOTES.get(mode, f"Sign-on mode {mode!r}: review by hand.")
        owner = owner_for(a, owners)
        direct = a.get("assignedUsersDirect")
        direct_ids = direct if direct is not None else a.get("assignedUsers", [])
        rows.append({
            "okta_app_id": a.get("id"),
            "app_name": a.get("label") or a.get("name"),
            "sign_on_mode": mode,
            "status": a.get("status") or "",
            "owner": owner or "MISSING",
            "sp_entity_id": sso.get("audience", "") if saml else "",
            "sp_acs_url": sso.get("ssoAcsUrl", "") if saml else "",
            "name_id_format": sso.get("subjectNameIdFormat", "") if saml else "",
            "name_id_template": sso.get("subjectNameIdTemplate", "") if saml else "",
            "okta_idp_issuer": sso.get("idpIssuer", "") if saml else "",
            "okta_metadata_path": (meta_base + sso["oktaMetadataPath"])
            if saml and sso.get("oktaMetadataPath") else "",
            "entra_identifier": entra["identifier"] if saml else "",
            "entra_login_url": entra["login_url"] if saml else "",
            "entra_metadata_url": entra["metadata_url"] if saml else "",
            "assigned_groups": ";".join(
                groups[g]["name"] for g in a.get("assignedGroups", [])
                if g in groups),
            "assigned_users_direct": ";".join(
                users[u]["login"] for u in direct_ids
                if u in users and users[u].get("login"))
            if direct is not None else "(scope not exported)",
            "assigned_users_total": len(a.get("assignedUsers", [])),
            "cutover_notes": note,
        })
    return rows


def build_plan(inv: dict, tenant: str, owners: dict | None = None) -> dict:
    """Machine-readable recreation plan (input for cutover_tracker.py)."""
    owners = owners or {}
    groups = by_id(inv["groups"])
    plan = {"tenant": tenant, "apps": [], "missingOwners": []}
    for a in inv["apps"]:
        owner = owner_for(a, owners)
        name = a.get("label") or a.get("name")
        if not owner:
            plan["missingOwners"].append({"oktaAppId": a["id"], "name": name})
        plan["apps"].append({
            "oktaAppId": a["id"],
            "name": name,
            "signOnMode": a.get("signOnMode"),
            "owner": owner,
            "assignedGroups": [groups[g]["name"]
                               for g in a.get("assignedGroups", [])
                               if g in groups],
            "assignedUserCount": len(a.get("assignedUsers", [])),
        })
    return plan


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Emit the app-owner handoff CSV and a recreation plan.")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("--tenant", default="",
                   help="Entra tenant GUID used in the Entra SAML values")
    p.add_argument("--owners",
                   help="CSV with okta_app_id or app_name, and owner")
    p.add_argument("-o", "--output",
                   help="write mapping CSV here (default: stdout)")
    p.add_argument("--plan", help="write recreation plan JSON here")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else \
        (lambda m: print(m, file=sys.stderr))
    inv = load_inventory(args.inventory)
    owners = load_owners(args.owners)
    rows = build_rows(inv, args.tenant, owners)
    if not is_guid(args.tenant):
        log("note: --tenant is not a tenant GUID; Entra values use "
            "<tenant-guid> placeholders")

    with csv_writer(args.output, HEADERS) as w:
        w.writeheader()
        w.writerows(rows)
    if args.output and args.output != "-":
        log(f"mapping table: {len(rows)} apps -> {args.output}")
    missing = [r["app_name"] for r in rows if r["owner"] == "MISSING"]
    if missing:
        log(f"{len(missing)} app(s) have no owner: {', '.join(missing)}")

    if args.plan:
        write_json(args.plan, build_plan(inv, args.tenant, owners))
        log(f"recreation plan -> {args.plan}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
