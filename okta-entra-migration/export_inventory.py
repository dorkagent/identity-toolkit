#!/usr/bin/env python3
"""LIFE-40: Export a complete migration inventory from Okta.

Default (offline) mode converts a local raw-Okta dump to the shared JSON
contract -- no network, no credentials. Live mode (``--live``) pages the
Okta Management API for large tenants and emits the same contract.

Examples:
    python3 export_inventory.py                       # offline, uses fixtures
    python3 export_inventory.py --raw mydump.json -o inv.json
    OKTA_DOMAIN=https://x.okta.com OKTA_API_TOKEN=... \\
        python3 export_inventory.py --live -o inv.json

Env (live mode only): OKTA_DOMAIN, OKTA_API_TOKEN (SSWS token minted from
a read-only Okta admin account). OAuth client-credentials is not supported
(Okta's Org Authorization Server requires private_key_jwt for service apps).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import new_inventory, save_inventory  # noqa: E402
from okta_api import OktaClient  # noqa: E402
from tenant_guard import check_okta_org  # noqa: E402

FIXTURE_RAW = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-raw.sample.json")


# ---------------------------------------------------------------- raw->contract

def contract_user(raw: dict, group_ids: list, app_ids: list) -> dict:
    p = raw.get("profile", {})
    creds = raw.get("credentials") or {}
    provider = creds.get("provider") or {}
    return {
        "id": raw.get("id"),
        "login": p.get("login"),
        "email": p.get("email"),
        "firstName": p.get("firstName"),
        "lastName": p.get("lastName"),
        "status": raw.get("status"),
        "userType": p.get("userType", "USER"),
        # Identity source: "OKTA", "ACTIVE_DIRECTORY", "LDAP", ...
        # AD/LDAP-mastered users must NOT get cloud duplicates in Entra --
        # they arrive via Entra Connect sync instead (see import_users.py).
        "credentialProvider": provider.get("type"),
        "department": p.get("department"),
        "title": p.get("title"),
        "manager": p.get("manager"),
        "groups": group_ids,
        "apps": app_ids,
        "profile": p,
    }


def contract_group(raw: dict, members: list, assigned_apps: list,
                   rule: dict | None) -> dict:
    p = raw.get("profile", {})
    return {
        "id": raw.get("id"),
        "name": p.get("name"),
        "description": p.get("description", ""),
        "type": raw.get("type", "OKTA_GROUP"),
        "members": members,
        "assignedApps": assigned_apps,
        "dynamicRule": (rule or {}).get("expression"),
        "dynamicRuleStatus": (rule or {}).get("status"),
    }


def contract_app(raw: dict, assigned_groups: list, assigned_users: list) -> dict:
    settings = raw.get("settings", {}) or {}
    sso = settings.get("signOn", {}) or {}
    oauth = settings.get("oauthClient", {}) or {}
    app = settings.get("app", {}) or {}
    sso_out = {
        "issuer": f"http://www.okta.com/{sso.get('issuerSuffix', raw.get('id'))}",
        "ssoUrl": sso.get("ssoUrl"),
        "audience": sso.get("audience"),
        "subjectNameIdFormat": sso.get("subjectNameIdFormat"),
        "url": app.get("url"),
        "clientId": oauth.get("client_id"),
        "grantTypes": oauth.get("grant_types"),
        "redirectUris": oauth.get("redirect_uris"),
    }
    sso_out = {k: v for k, v in sso_out.items() if v}
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "label": raw.get("label"),
        "status": raw.get("status"),
        "signOnMode": raw.get("signOnMode"),
        "sso": sso_out,
        "assignedGroups": assigned_groups,
        "assignedUsers": assigned_users,
        "owner": (raw.get("_embedded", {}) or {}).get("owner"),
    }


def raw_to_contract(raw: dict, source: dict) -> dict:
    """Convert raw Okta API shapes (fixture or live responses) to the contract."""
    inv = new_inventory(source)
    users = raw.get("users", [])
    groups = raw.get("groups", [])
    apps = raw.get("apps", [])
    group_members = raw.get("groupMembers", {})
    app_users = raw.get("appUsers", {})
    app_groups = raw.get("appGroups", {})
    group_rules = raw.get("groupRules", {})

    user_groups: dict[str, list] = {u["id"]: [] for u in users}
    for gid, members in group_members.items():
        for uid in members:
            user_groups.setdefault(uid, []).append(gid)

    user_apps: dict[str, list] = {u["id"]: [] for u in users}
    for aid, members in app_users.items():
        for uid in members:
            user_apps.setdefault(uid, []).append(aid)

    group_apps: dict[str, list] = {g["id"]: [] for g in groups}
    for aid, gids in app_groups.items():
        for gid in gids:
            group_apps.setdefault(gid, []).append(aid)

    for u in users:
        inv["users"].append(contract_user(
            u, user_groups.get(u["id"], []), user_apps.get(u["id"], [])))
    for g in groups:
        inv["groups"].append(contract_group(
            g, group_members.get(g["id"], []),
            group_apps.get(g["id"], []), group_rules.get(g["id"])))
    for a in apps:
        inv["apps"].append(contract_app(
            a, app_groups.get(a["id"], []), app_users.get(a["id"], [])))

    for p in raw.get("policies", []):
        inv["policies"].append({
            "id": p.get("id"), "name": p.get("name"),
            "type": p.get("type"), "status": p.get("status"),
            "rules": [{"id": r.get("id"), "name": r.get("name"),
                       "status": r.get("status"),
                       "conditions": r.get("conditions", {})}
                      for r in (p.get("rules") or [])],
        })
    for t in raw.get("apiTokens", []):
        inv["apiTokens"].append({
            "id": t.get("id"), "name": t.get("name"),
            "clientName": t.get("clientName"), "userId": t.get("userId"),
            "created": t.get("created"), "lastUpdated": t.get("lastUpdated"),
            "expiresAt": t.get("expiresAt"),
        })
    for a in apps:
        if a.get("signOnMode") == "OPENID_CONNECT":
            settings = a.get("settings", {}) or {}
            oauth = settings.get("oauthClient", {}) or {}
            inv["oauthApps"].append({
                "id": a.get("id"), "name": a.get("name"),
                "label": a.get("label"), "status": a.get("status"),
                "clientId": oauth.get("client_id"),
                "grantTypes": oauth.get("grant_types", []),
                "redirectUris": oauth.get("redirect_uris", []),
                "scopes": [],
            })
    return inv


# ---------------------------------------------------------------- live export

POLICY_TYPES = ("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "OAUTH_AUTHORIZATION_POLICY")


def live_export(client: OktaClient, progress) -> dict:
    users = list(client.list_users()); progress(f"users: {len(users)}")
    groups = list(client.list_groups()); progress(f"groups: {len(groups)}")
    apps = list(client.list_apps()); progress(f"apps: {len(apps)}")

    group_members = {}
    for g in groups:
        group_members[g["id"]] = [u["id"] for u in client.list_group_members(g["id"])]
    progress("group memberships collected")

    app_users, app_groups = {}, {}
    for a in apps:
        app_users[a["id"]] = [u["id"] for u in client.list_app_users(a["id"])]
        app_groups[a["id"]] = [g["id"] for g in client.list_app_groups(a["id"])]
    progress("app assignments collected")

    policies = []
    for ptype in POLICY_TYPES:
        for p in client.list_policies(ptype):
            p = dict(p)
            p["rules"] = list(client.list_policy_rules(p["id"]))
            policies.append(p)
    progress(f"policies: {len(policies)}")

    tokens = list(client.list_api_tokens())
    progress(f"api tokens: {len(tokens)}")

    raw = {
        "users": users, "groups": groups, "apps": apps,
        "groupMembers": group_members, "appUsers": app_users,
        "appGroups": app_groups, "groupRules": {},
        "policies": policies, "apiTokens": tokens,
    }
    return raw_to_contract(
        raw, {"live": True, "oktaDomain": client.base_url,
              "authMode": getattr(client, "auth_mode", "unknown")})


# ---------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Export a complete Okta migration inventory as JSON.")
    p.add_argument("--raw", default=FIXTURE_RAW,
                   help="local raw-Okta dump (JSON) to convert "
                        "(default: bundled fixture)")
    p.add_argument("--live", action="store_true",
                   help="page the live Okta Management API instead "
                        "(needs OKTA_DOMAIN + OKTA_API_TOKEN, an SSWS token)")
    p.add_argument("-o", "--output", default="okta-inventory.json",
                   help="where to write the contract JSON")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    if args.live:
        client = OktaClient()
        if check_okta_org(client, log) is None:
            return 2
        inv = live_export(client, log)
    else:
        with open(args.raw, encoding="utf-8") as fh:
            raw = json.load(fh)
        inv = raw_to_contract(raw, {"live": False, "rawFile": args.raw})
        log(f"converted {args.raw}")
    save_inventory(inv, args.output)
    log(f"wrote {args.output}: {len(inv['users'])} users, "
        f"{len(inv['groups'])} groups, {len(inv['apps'])} apps, "
        f"{len(inv['policies'])} policies, {len(inv['apiTokens'])} api tokens, "
        f"{len(inv['oauthApps'])} oauth apps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
