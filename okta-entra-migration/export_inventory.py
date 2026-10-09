#!/usr/bin/env python3
"""Export an Okta org into the kit's JSON inventory.

Offline (default) converts a local raw-Okta dump to the inventory, with no
network and no credentials. ``--live`` pages the Okta Management API
(read-only) and produces the same inventory.

Live exports save each section to a checkpoint directory as soon as it is
read (``<output>.parts/`` by default, files 0600). Per-object sections
such as group memberships are saved every few dozen objects. If the run
stops partway, ``--resume`` picks up from the checkpoint instead of
starting again. A section that fails (an endpoint your token's role can't
read, a policy type your org doesn't have) is recorded under
``exportErrors`` and the export carries on; the script exits 1 when
anything is missing so a pipeline notices.

Examples:
    python3 export_inventory.py                       # offline, uses fixtures
    python3 export_inventory.py --raw mydump.json -o inv.json
    OKTA_DOMAIN=https://x.okta.com OKTA_API_TOKEN=... \\
        python3 export_inventory.py --live -o inv.json
    python3 export_inventory.py --live -o inv.json --resume
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import new_inventory, save_inventory  # noqa: E402
from okta_api import OktaAuthError, OktaClient  # noqa: E402
from secure_io import atomic_write_text  # noqa: E402
from tenant_guard import check_okta_org  # noqa: E402

FIXTURE_RAW = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-raw.sample.json")

# Every value of the PolicyType enum that GET /api/v1/policies accepts
# (Okta Management OpenAPI spec, PolicyType). Orgs without a feature flag
# return 400 for some of these; that is recorded, not fatal.
# OAUTH_AUTHORIZATION_POLICY is *not* here: it lives under
# /api/v1/authorizationServers/{id}/policies.
POLICY_TYPES = (
    "ACCESS_POLICY", "ENTITY_RISK", "IDP_DISCOVERY", "MFA_ENROLL",
    "OKTA_SIGN_ON", "PASSWORD", "POST_AUTH_SESSION", "PROFILE_ENROLLMENT",
    "DEVICE_SIGNAL_COLLECTION", "SESSION_VIOLATION_DETECTION",
    "CLIENT_UPDATE", "IDENTITY_CLAIM_SOURCING",
)

# SAML sign-on settings worth handing to an app owner
# (SamlApplicationSettingsSignOn in the Okta OpenAPI spec).
SAML_FIELDS = ("ssoAcsUrl", "audience", "recipient", "destination",
               "idpIssuer", "spIssuer", "subjectNameIdTemplate",
               "subjectNameIdFormat", "signatureAlgorithm",
               "digestAlgorithm", "assertionSigned", "responseSigned")


# ---------------------------------------------------------------- raw->contract

def contract_user(raw: dict, group_ids: list, app_ids: list) -> dict:
    p = raw.get("profile", {}) or {}
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
        # Identity source: OKTA, ACTIVE_DIRECTORY, LDAP, FEDERATION, IMPORT,
        # SOCIAL. AD/LDAP-mastered users must not get cloud duplicates in
        # Entra; they arrive through Entra Connect / Cloud Sync instead.
        "credentialProvider": provider.get("type"),
        "department": p.get("department"),
        "title": p.get("title"),
        "manager": p.get("manager"),
        "countryCode": p.get("countryCode"),
        "groups": group_ids,
        "apps": app_ids,
        "profile": p,
    }


def contract_rule(raw: dict) -> dict:
    """Okta GroupRule -> contract rule."""
    cond = raw.get("conditions") or {}
    people = cond.get("people") or {}
    actions = (raw.get("actions") or {}).get("assignUserToGroups") or {}
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "status": raw.get("status"),
        "expression": (cond.get("expression") or {}).get("value"),
        "targetGroupIds": list(actions.get("groupIds") or []),
        "excludedUserIds": list(((people.get("users") or {})
                                 .get("exclude")) or []),
        "excludedGroupIds": list(((people.get("groups") or {})
                                  .get("exclude")) or []),
    }


def normalize_rules(group_rules) -> list[dict]:
    """Accept the real GroupRule list, or the old {groupId: {...}} map."""
    if isinstance(group_rules, dict):
        out = []
        for gid, r in group_rules.items():
            out.append({"id": f"legacy-{gid}", "name": None,
                        "status": r.get("status"),
                        "expression": r.get("expression"),
                        "targetGroupIds": [gid], "excludedUserIds": [],
                        "excludedGroupIds": []})
        return out
    return [contract_rule(r) for r in (group_rules or [])]


def contract_group(raw: dict, members: list, assigned_apps: list,
                   rules: list[dict] | None) -> dict:
    p = raw.get("profile", {}) or {}
    rules = rules or []
    single = rules[0] if len(rules) == 1 else None
    return {
        "id": raw.get("id"),
        "name": p.get("name"),
        "description": p.get("description", "") or "",
        "type": raw.get("type", "OKTA_GROUP"),
        "members": members,
        "assignedApps": assigned_apps,
        "ruleIds": [r["id"] for r in rules],
        # Kept for older consumers: the expression when exactly one rule
        # targets the group, else None (see ruleIds / groupRules).
        "dynamicRule": single["expression"] if single else None,
        "dynamicRuleStatus": single["status"] if single else None,
    }


def contract_app(raw: dict, assigned_groups: list, assigned_users: list,
                 user_scopes: dict | None = None) -> dict:
    settings = raw.get("settings", {}) or {}
    sso = settings.get("signOn", {}) or {}
    oauth = settings.get("oauthClient", {}) or {}
    app = settings.get("app", {}) or {}
    sso_out = {k: sso.get(k) for k in SAML_FIELDS if sso.get(k) is not None}
    sso_out.update({k: v for k, v in {
        "url": app.get("url"),
        "clientId": oauth.get("client_id"),
        "grantTypes": oauth.get("grant_types"),
        "redirectUris": oauth.get("redirect_uris"),
    }.items() if v})
    if raw.get("signOnMode") in ("SAML_2_0", "SAML_1_1"):
        # Admin-API path to the app's IdP metadata (needs the API token).
        sso_out["oktaMetadataPath"] = \
            f"/api/v1/apps/{raw.get('id')}/sso/saml/metadata"
    direct = None
    if user_scopes is not None:
        direct = [u for u in assigned_users if user_scopes.get(u) == "USER"]
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "label": raw.get("label"),
        "status": raw.get("status"),
        "signOnMode": raw.get("signOnMode"),
        "sso": sso_out,
        "assignedGroups": assigned_groups,
        "assignedUsers": assigned_users,
        # Users assigned directly (AppUser.scope == USER), when known.
        # None means the export didn't record scope.
        "assignedUsersDirect": direct,
        # Okta has no app-owner field. migrate_apps.py joins owners from a
        # CSV you supply (--owners).
        "owner": "",
    }


def raw_to_contract(raw: dict, source: dict) -> dict:
    """Convert raw Okta API shapes (fixture or live responses) to the contract."""
    inv = new_inventory(source)
    users = raw.get("users", [])
    groups = raw.get("groups", [])
    apps = raw.get("apps", [])
    group_members = raw.get("groupMembers", {})
    app_users = raw.get("appUsers", {})
    app_user_scopes = raw.get("appUserScopes", {})
    app_groups = raw.get("appGroups", {})
    rules = normalize_rules(raw.get("groupRules", []))
    inv["groupRules"] = rules

    rules_by_group: dict[str, list] = {}
    for r in rules:
        for gid in r["targetGroupIds"]:
            rules_by_group.setdefault(gid, []).append(r)

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
            group_apps.get(g["id"], []), rules_by_group.get(g["id"])))
    for a in apps:
        inv["apps"].append(contract_app(
            a, app_groups.get(a["id"], []), app_users.get(a["id"], []),
            app_user_scopes.get(a["id"])))

    for p in raw.get("policies", []):
        inv["policies"].append({
            "id": p.get("id"), "name": p.get("name"),
            "type": p.get("type"), "status": p.get("status"),
            "system": p.get("system"),
            "rules": [{"id": r.get("id"), "name": r.get("name"),
                       "status": r.get("status"),
                       "conditions": r.get("conditions") or {},
                       "actions": r.get("actions") or {}}
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
    inv["exportErrors"] = dict(raw.get("exportErrors") or {})
    return inv


# ---------------------------------------------------------------- live export

class Checkpoint:
    """One 0600 JSON file per export section under a directory."""

    def __init__(self, directory: str | None, resume: bool):
        self.dir = directory
        self.resume = resume
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.dir, f"{name}.json")

    def load(self, name: str):
        if not (self.dir and self.resume and os.path.exists(self._path(name))):
            return None
        with open(self._path(name), encoding="utf-8") as fh:
            return json.load(fh)

    def save(self, name: str, value) -> None:
        if self.dir:
            atomic_write_text(self._path(name),
                              json.dumps(value, default=str) + "\n")


def _section_error(e: Exception) -> str:
    status = getattr(e, "status_code", None)
    if status is None and getattr(e, "response", None) is not None:
        status = e.response.status_code
    return f"HTTP {status}: {e}" if status else str(e)


def live_export(client: OktaClient, progress, checkpoint: Checkpoint | None = None,
                flush_every: int = 25) -> dict:
    cp = checkpoint or Checkpoint(None, False)
    errors: dict[str, str] = dict(cp.load("_errors") or {})

    def fatal(e: Exception) -> bool:
        return isinstance(e, OktaAuthError) and e.status_code == 401

    def list_section(name: str, fetch):
        cached = cp.load(name)
        if cached is not None and cached.get("complete"):
            progress(f"{name}: {len(cached['items'])} (from checkpoint)")
            return cached["items"]
        try:
            items = list(fetch())
        except Exception as e:  # noqa: BLE001 - record, keep exporting
            if fatal(e):
                raise
            errors[name] = _section_error(e)
            cp.save("_errors", errors)
            progress(f"{name}: FAILED ({errors[name]})")
            return []
        errors.pop(name, None)
        cp.save(name, {"complete": True, "items": items})
        cp.save("_errors", errors)
        progress(f"{name}: {len(items)}")
        return items

    def map_section(name: str, keys: list[str], fetch):
        """{key: fetch(key)} with periodic checkpointing and resume."""
        cached = cp.load(name) or {}
        done = dict(cached.get("items") or {})
        failed = {}
        todo = [k for k in keys if k not in done]
        for n, key in enumerate(todo, 1):
            try:
                done[key] = fetch(key)
            except Exception as e:  # noqa: BLE001 - record, keep exporting
                if fatal(e):
                    cp.save(name, {"complete": False, "items": done})
                    raise
                failed[key] = _section_error(e)
            if n % flush_every == 0:
                cp.save(name, {"complete": False, "items": done})
        cp.save(name, {"complete": not failed, "items": done})
        if failed:
            errors[name] = (f"{len(failed)} of {len(keys)} failed, e.g. "
                            f"{next(iter(failed.items()))}")
        else:
            errors.pop(name, None)
        cp.save("_errors", errors)
        progress(f"{name}: {len(done)}/{len(keys)}")
        return done

    users = list_section("users", client.list_users)
    groups = list_section("groups", client.list_groups)
    group_rules = list_section("groupRules", client.list_group_rules)
    apps = list_section("apps", client.list_apps)

    group_members = map_section(
        "groupMembers", [g["id"] for g in groups],
        lambda gid: [u["id"] for u in client.list_group_members(gid)])

    def app_users_fetch(aid):
        return [{"id": u["id"], "scope": u.get("scope")}
                for u in client.list_app_users(aid)]
    app_users_raw = map_section("appUsers", [a["id"] for a in apps],
                                app_users_fetch)
    app_groups = map_section(
        "appGroups", [a["id"] for a in apps],
        lambda aid: [g["id"] for g in client.list_app_groups(aid)])

    def policies_fetch(ptype):
        try:
            found = list(client.list_policies(ptype))
        except requests.HTTPError as e:
            # 400 "Invalid policy type specified" means the org doesn't
            # have that feature; it's not an export failure.
            if e.response is not None and e.response.status_code == 400:
                return {"unavailable": str(e)[:200]}
            raise
        out = []
        for p in found:
            p = dict(p)
            p["rules"] = list(client.list_policy_rules(p["id"]))
            out.append(p)
        return out
    by_type = map_section("policies", list(POLICY_TYPES), policies_fetch)
    policies = [p for t in POLICY_TYPES
                if isinstance(by_type.get(t), list) for p in by_type[t]]
    unavailable = sorted(t for t, v in by_type.items() if isinstance(v, dict))

    tokens = list_section("apiTokens", client.list_api_tokens)

    raw = {
        "users": users, "groups": groups, "apps": apps,
        "groupMembers": group_members,
        "appUsers": {a: [u["id"] for u in us] for a, us in app_users_raw.items()},
        "appUserScopes": {a: {u["id"]: u.get("scope") for u in us}
                          for a, us in app_users_raw.items()},
        "appGroups": app_groups, "groupRules": group_rules,
        "policies": policies, "apiTokens": tokens, "exportErrors": errors,
    }
    return raw_to_contract(
        raw, {"live": True, "oktaDomain": client.base_url,
              "authMode": getattr(client, "auth_mode", "unknown"),
              "policyTypesUnavailable": unavailable})


# ---------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Export an Okta org into the kit's JSON inventory.")
    p.add_argument("--raw", default=FIXTURE_RAW,
                   help="local raw-Okta dump (JSON) to convert "
                        "(default: bundled fixture)")
    p.add_argument("--live", action="store_true",
                   help="page the live Okta Management API instead "
                        "(needs OKTA_DOMAIN + OKTA_API_TOKEN)")
    p.add_argument("-o", "--output", default="okta-inventory.json",
                   help="where to write the inventory JSON")
    p.add_argument("--checkpoint-dir",
                   help="live mode: where to save sections as they finish "
                        "(default: <output>.parts)")
    p.add_argument("--resume", action="store_true",
                   help="live mode: reuse sections already in the "
                        "checkpoint directory")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None, client=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    if args.live:
        client = client or OktaClient()
        org = check_okta_org(client, log)
        if org is None:
            return 2
        cp = Checkpoint(args.checkpoint_dir or args.output + ".parts",
                        args.resume)
        try:
            inv = live_export(client, log, cp)
        except OktaAuthError as e:
            print(f"error: {e}\nWhat was read so far is in {cp.dir}; rerun "
                  f"with --resume once the token is fixed.", file=sys.stderr)
            return 2
        inv["source"]["oktaOrgId"] = org.get("id")
    else:
        with open(args.raw, encoding="utf-8") as fh:
            raw = json.load(fh)
        inv = raw_to_contract(raw, {"live": False, "rawFile": args.raw})
        log(f"converted {args.raw}")
    save_inventory(inv, args.output)
    log(f"wrote {args.output}: {len(inv['users'])} users, "
        f"{len(inv['groups'])} groups, {len(inv['groupRules'])} group rules, "
        f"{len(inv['apps'])} apps, {len(inv['policies'])} policies, "
        f"{len(inv['apiTokens'])} api tokens, "
        f"{len(inv['oauthApps'])} oauth apps")
    if inv["exportErrors"]:
        print(f"warning: {len(inv['exportErrors'])} section(s) incomplete "
              f"(see exportErrors in {args.output}):", file=sys.stderr)
        for section, msg in inv["exportErrors"].items():
            print(f"  - {section}: {msg}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
