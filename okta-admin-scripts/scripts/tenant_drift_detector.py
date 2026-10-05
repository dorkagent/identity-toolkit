#!/usr/bin/env python3
"""Tenant drift detector (DHQ-89).

Captures point-in-time snapshots of tenant configuration (policies + rules,
network zones, authorization servers, apps + assignments, admin role grants)
and diffs two snapshots to show configuration drift.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/tenant_drift_detector.py --snapshot
    python scripts/python/tenant_drift_detector.py --list
    python scripts/python/tenant_drift_detector.py --diff snap-old.json snap-new.json
    python scripts/python/tenant_drift_detector.py --diff snap-old.json snap-new.json --json --output drift.json

Volatile fields (created, lastUpdated, _links, lastLogin, statusChanged,
passwordChanged) are ignored recursively when diffing, so only real
configuration drift shows up.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError

VOLATILE_FIELDS = {"created", "lastUpdated", "_links", "lastLogin",
                   "statusChanged", "passwordChanged"}

POLICY_TYPES = ["OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL", "IDP_DISCOVERY"]

# group -> (key function, display-name function)
GROUP_KEYS = {
    "policies": (lambda r: r.get("id"), lambda r: r.get("name") or "?"),
    "zones": (lambda r: r.get("id"), lambda r: r.get("name") or "?"),
    "auth_servers": (lambda r: r.get("id"), lambda r: r.get("name") or "?"),
    "apps": (lambda r: r.get("id"), lambda r: r.get("label") or "?"),
    "admin_roles": (lambda r: f"{r.get('user_id')}::{r.get('role_type')}",
                    lambda r: f"{r.get('login')} / {r.get('role_type')}"),
}


def slugify(domain: str) -> str:
    slug = re.sub(r"^https?://", "", domain).rstrip("/")
    return re.sub(r"[^a-zA-Z0-9]+", "-", slug).strip("-").lower()


def app_user_ids(client: OktaClient, app_id: str) -> list:
    """Return the user ids assigned to an app.

    AppUser records carry the user id in _links.user.href; fall back to the
    app-user record id when the link is missing.
    """
    ids = []
    for au in client.list_app_users(app_id):
        href = ((au.get("_links") or {}).get("user") or {}).get("href") or ""
        uid = href.rstrip("/").split("/")[-1] if href else au.get("id")
        if uid:
            ids.append(uid)
    return sorted(set(ids))


def capture_snapshot(client: OktaClient) -> dict:
    policies = []
    for ptype in POLICY_TYPES:
        n = 0
        for policy in client.list_policies(ptype):
            n += 1
            rules = []
            for rule in client.list_policy_rules(policy["id"]):
                rules.append({
                    "id": rule.get("id"),
                    "name": rule.get("name"),
                    "actions": rule.get("actions"),
                    "conditions": rule.get("conditions"),
                })
            policies.append({
                "id": policy.get("id"),
                "name": policy.get("name"),
                "type": policy.get("type"),
                "rules": rules,
            })
        print(f"... captured {n} {ptype} policies", file=sys.stderr)

    zones = list(client.list_zones())
    print(f"... captured {len(zones)} zones", file=sys.stderr)

    auth_servers = list(client.list_auth_servers())
    print(f"... captured {len(auth_servers)} auth servers", file=sys.stderr)

    apps = []
    all_apps = list(client.list_apps())
    for i, app in enumerate(all_apps, 1):
        apps.append({
            "id": app.get("id"),
            "label": app.get("label"),
            "name": app.get("name"),
            "signOnMode": app.get("signOnMode"),
            "assigned_user_ids": app_user_ids(client, app["id"]),
        })
        if i % 25 == 0:
            print(f"... captured assignments for {i}/{len(all_apps)} apps",
                  file=sys.stderr)
    print(f"... captured {len(apps)} apps", file=sys.stderr)

    admin_roles = []
    n_users = 0
    for user in client.list_users():
        n_users += 1
        login = (user.get("profile") or {}).get("login")
        for role in client.list_user_roles(user["id"]):
            admin_roles.append({
                "user_id": user.get("id"),
                "login": login,
                "role_type": role.get("type"),
                "grant_date": role.get("created"),
            })
    print(f"... captured {len(admin_roles)} admin role grants "
          f"({n_users} users)", file=sys.stderr)

    return {
        "meta": {
            "domain": client.base_url,
            "snapshot_id": datetime.now(timezone.utc)
                .strftime("%Y%m%d-%H%M%S"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "script": "tenant_drift_detector.py",
        },
        "data": {
            "policies": policies,
            "zones": zones,
            "auth_servers": auth_servers,
            "apps": apps,
            "admin_roles": admin_roles,
        },
    }


def normalize(obj):
    """Recursively strip volatile fields so only config drift is compared."""
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()
                if k not in VOLATILE_FIELDS}
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    return obj


def leaf_diff(old, new, path: str = "") -> list:
    """Return [(path, old_value, new_value)] leaf differences."""
    diffs = []
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            sub = f"{path}.{key}" if path else key
            if key not in old:
                diffs.append((sub, "<absent>", new[key]))
            elif key not in new:
                diffs.append((sub, old[key], "<absent>"))
            else:
                diffs += leaf_diff(old[key], new[key], sub)
    elif isinstance(old, list) and isinstance(new, list):
        if old != new:
            diffs.append((path, old, new))
    elif old != new:
        diffs.append((path, old, new))
    return diffs


def diff_snapshots(old: dict, new: dict) -> dict:
    """Compare grouped by resource type: added / removed / changed."""
    result = {}
    for group, (key_fn, _name_fn) in GROUP_KEYS.items():
        old_map = {key_fn(r): r for r in (old.get("data") or {}).get(group, [])}
        new_map = {key_fn(r): r for r in (new.get("data") or {}).get(group, [])}
        added = [new_map[k] for k in new_map if k not in old_map]
        removed = [old_map[k] for k in old_map if k not in new_map]
        changed = []
        for k in old_map:
            if k in new_map:
                o, n = normalize(old_map[k]), normalize(new_map[k])
                if o != n:
                    changed.append({
                        "key": k,
                        "resource": new_map[k],
                        "changes": [
                            {"path": p, "old": ov, "new": nv}
                            for p, ov, nv in leaf_diff(o, n)
                        ],
                    })
        result[group] = {"added": added, "removed": removed, "changed": changed}
    return result


def _short(value) -> str:
    s = json.dumps(value, default=str)
    return s if len(s) <= 90 else s[:87] + "..."


def print_diff(diff: dict):
    for group, (key_fn, name_fn) in GROUP_KEYS.items():
        sect = diff[group]
        n_add, n_rem, n_chg = (len(sect["added"]), len(sect["removed"]),
                               len(sect["changed"]))
        print(f"\n=== {group} "
              f"(+{n_add} -{n_rem} ~{n_chg}) ===")
        for r in sect["added"]:
            print(f"+ {name_fn(r)}  [id={key_fn(r)}]")
        for r in sect["removed"]:
            print(f"- {name_fn(r)}  [id={key_fn(r)}]")
        for c in sect["changed"]:
            print(f"~ {name_fn(c['resource'])}  [id={c['key']}]")
            for ch in c["changes"]:
                print(f"    {ch['path']}: {_short(ch['old'])} "
                      f"-> {_short(ch['new'])}")
    total = sum(len(diff[g][k]) for g in diff for k in ("added", "removed",
                                                       "changed"))
    print(f"\ntotal changes: {total}")


def resolve_path(p: str, snapshot_dir: str) -> str:
    if os.path.isfile(p):
        return p
    return os.path.join(snapshot_dir, p)


def cmd_list(snapshot_dir: str):
    files = sorted(f for f in os.listdir(snapshot_dir)
                   if f.endswith(".json")) if os.path.isdir(snapshot_dir) else []
    if not files:
        print(f"no snapshots in {snapshot_dir}")
        return
    print(f"{'FILE':60} {'TIMESTAMP':28} DOMAIN")
    print("-" * 110)
    for f in files:
        ts, domain = "?", "?"
        try:
            with open(os.path.join(snapshot_dir, f), encoding="utf-8") as fh:
                meta = json.load(fh).get("meta") or {}
            ts = meta.get("timestamp", "?")
            domain = meta.get("domain", "?")
        except (OSError, ValueError):
            pass
        print(f"{f[:60]:60} {str(ts)[:28]:28} {domain}")


def main():
    p = argparse.ArgumentParser(
        description="Capture Okta tenant config snapshots and diff them "
                    "to show configuration drift.")
    p.add_argument("--snapshot", action="store_true",
                   help="capture a snapshot into --snapshot-dir")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                   help="diff two snapshot files")
    p.add_argument("--list", action="store_true",
                   help="list snapshots in --snapshot-dir")
    p.add_argument("--snapshot-dir", default="./snapshots",
                   help="directory for snapshot files (default ./snapshots)")
    p.add_argument("--json", action="store_true",
                   help="emit JSON instead of a human-readable diff")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    actions = [args.snapshot, bool(args.diff), args.list]
    if sum(actions) != 1:
        p.error("exactly one of --snapshot, --diff, --list is required")

    os.makedirs(args.snapshot_dir, exist_ok=True)

    if args.list:
        cmd_list(args.snapshot_dir)
        return

    if args.diff:
        old_path = resolve_path(args.diff[0], args.snapshot_dir)
        new_path = resolve_path(args.diff[1], args.snapshot_dir)
        with open(old_path, encoding="utf-8") as f:
            old = json.load(f)
        with open(new_path, encoding="utf-8") as f:
            new = json.load(f)
        diff = diff_snapshots(old, new)
        if args.json:
            report = json.dumps(diff, indent=2, default=str)
        else:
            print_diff(diff)
            report = ""
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report if args.json else "")
            print(f"\nwrote {args.output}", file=sys.stderr)
        elif args.json:
            print(report)
        return

    # --snapshot
    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    snap = capture_snapshot(client)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{slugify(client.base_url)}-{stamp}.json"
    path = os.path.join(args.snapshot_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2, default=str)
    print(f"snapshot written to {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
