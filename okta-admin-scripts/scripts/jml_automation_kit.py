#!/usr/bin/env python3
"""Joiner / Mover / Leaver provisioning kit.

Reads a CSV of user changes and applies them to Okta. DRY-RUN BY DEFAULT:
without --apply it only reports what WOULD change. Re-runs are idempotent --
already-correct state is skipped, not re-applied.

CSV columns:
    login, firstName, lastName, email (optional, falls back to login),
    groups (semicolon-separated group names), apps (semicolon-separated app labels)

Modes:
    joiner  create the user (deactivated, via ?activate=false) or update the
            profile of an existing one; add group memberships and app
            assignments.
    mover   update profile; add missing groups/apps from the CSV; remove
            extras ONLY with --prune.
    leaver  deactivate the user; report remaining app assignments and group
            memberships for cleanup.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/jml_automation_kit.py --mode joiner --csv hires.csv
    python scripts/python/jml_automation_kit.py --mode joiner --csv hires.csv --apply
    python scripts/python/jml_automation_kit.py --mode mover --csv moves.csv --apply --prune
    python scripts/python/jml_automation_kit.py --mode leaver --csv exits.csv --apply
    python scripts/python/jml_automation_kit.py --mode joiner --csv hires.csv --json --output plan.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests
from lib.okta_client import OktaClient, OktaAuthError


# ---- helpers ----

def parse_list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(";") if v.strip()]


def check_exists(client: OktaClient, path: str) -> bool:
    """True if GET path returns 200; False on 404; re-raise otherwise."""
    try:
        client._request("GET", path)
        return True
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return False
        raise


def find_group(client: OktaClient, name: str) -> dict | None:
    for g in client.list_groups(name):
        if (g.get("profile") or {}).get("name") == name:
            return g
    return None


def find_app(client: OktaClient, label: str) -> dict | None:
    for a in client.paged_get("/api/v1/apps", {"q": label}):
        if a.get("label") == label:
            return a
    return None


def current_groups(client: OktaClient, uid: str) -> dict:
    """name -> group dict for groups the user belongs to."""
    out = {}
    for g in client.paged_get(f"/api/v1/users/{uid}/groups"):
        name = (g.get("profile") or {}).get("name")
        if name:
            out[name] = g
    return out


def current_apps(client: OktaClient, uid: str) -> dict:
    """label -> app dict for apps assigned to the user."""
    out = {}
    for a in client.paged_get("/api/v1/apps", {"filter": f'user.id eq "{uid}"'}):
        if a.get("label"):
            out[a["label"]] = a
    return out


# ---- action log ----

class ActionLog:
    def __init__(self):
        self.actions: list[dict] = []

    def add(self, login: str, action: str, detail: str, status: str):
        self.actions.append({
            "login": login, "action": action, "detail": detail, "status": status,
        })

    def changed(self) -> int:
        return sum(1 for a in self.actions if a["status"] in ("done", "dry-run"))


def do_write(client: OktaClient, method: str, path: str, data: dict | None,
             log: ActionLog, login: str, action: str, detail: str, apply: bool):
    """Gate every write behind --apply; log what happened or would happen."""
    if not apply:
        log.add(login, action, f"WOULD {detail}", "dry-run")
        return
    getattr(client, method)(path, data)
    log.add(login, action, detail, "done")


# ---- per-mode processing ----

def sync_profile(client: OktaClient, log: ActionLog, login: str, user: dict,
                 row: dict, apply: bool):
    desired = {
        "firstName": (row.get("firstName") or "").strip(),
        "lastName": (row.get("lastName") or "").strip(),
        "email": (row.get("email") or "").strip() or login,
        "login": login,
    }
    profile = user.get("profile", {})
    changed = {k: v for k, v in desired.items() if profile.get(k) != v}
    if not changed:
        log.add(login, "update_profile", "profile already correct", "skipped")
        return
    detail = f"update profile: {', '.join(f'{k}={v}' for k, v in changed.items())}"
    new_profile = dict(profile)
    new_profile.update(desired)
    if not apply:
        log.add(login, "update_profile", f"WOULD {detail}", "dry-run")
        return
    client.put(f"/api/v1/users/{user['id']}", {"profile": new_profile})
    log.add(login, "update_profile", detail, "done")


def add_groups_apps(client: OktaClient, log: ActionLog, login: str, uid: str,
                    group_names: list, app_labels: list, apply: bool):
    for name in group_names:
        group = find_group(client, name)
        if group is None:
            log.add(login, "add_group", f"group not found: {name}", "error")
            continue
        if check_exists(client, f"/api/v1/groups/{group['id']}/users/{uid}"):
            log.add(login, "add_group", f"already member: {name}", "skipped")
            continue
        do_write(client, "post", f"/api/v1/groups/{group['id']}/users/{uid}", {},
                 log, login, "add_group", f"add to group: {name}", apply)
    for label in app_labels:
        app = find_app(client, label)
        if app is None:
            log.add(login, "assign_app", f"app not found: {label}", "error")
            continue
        if check_exists(client, f"/api/v1/apps/{app['id']}/users/{uid}"):
            log.add(login, "assign_app", f"already assigned: {label}", "skipped")
            continue
        do_write(client, "post", f"/api/v1/apps/{app['id']}/users", {"id": uid},
                 log, login, "assign_app", f"assign app: {label}", apply)


def process_joiner(client: OktaClient, row: dict, apply: bool) -> list[dict]:
    log = ActionLog()
    login = (row.get("login") or "").strip()
    if not login:
        log.add("?", "create_user", "row missing login", "error")
        return log.actions
    user = client.get_user_by_login(login)
    if user is None:
        profile = {
            "firstName": (row.get("firstName") or "").strip(),
            "lastName": (row.get("lastName") or "").strip(),
            "email": (row.get("email") or "").strip() or login,
            "login": login,
        }
        do_write(client, "post", "/api/v1/users?activate=false",
                 {"profile": profile}, log, login, "create_user",
                 f"create user (activate=false): {profile}", apply)
        # Groups/apps cannot be resolved without a user id on a dry run.
        for name in parse_list(row.get("groups")):
            log.add(login, "add_group", f"pending user creation: {name}", "skipped")
        for label in parse_list(row.get("apps")):
            log.add(login, "assign_app", f"pending user creation: {label}", "skipped")
        return log.actions
    sync_profile(client, log, login, user, row, apply)
    add_groups_apps(client, log, login, user["id"],
                    parse_list(row.get("groups")), parse_list(row.get("apps")), apply)
    return log.actions


def process_mover(client: OktaClient, row: dict, apply: bool, prune: bool) -> list[dict]:
    log = ActionLog()
    login = (row.get("login") or "").strip()
    if not login:
        log.add("?", "update_profile", "row missing login", "error")
        return log.actions
    user = client.get_user_by_login(login)
    if user is None:
        log.add(login, "update_profile", "user not found", "error")
        return log.actions
    uid = user["id"]
    sync_profile(client, log, login, user, row, apply)

    desired_groups = parse_list(row.get("groups"))
    desired_apps = parse_list(row.get("apps"))
    have_groups = current_groups(client, uid)
    have_apps = current_apps(client, uid)

    add_groups_apps(client, log, login, uid,
                    [g for g in desired_groups if g not in have_groups],
                    [a for a in desired_apps if a not in have_apps], apply)
    for name in [g for g in desired_groups if g in have_groups]:
        log.add(login, "add_group", f"already member: {name}", "skipped")
    for label in [a for a in desired_apps if a in have_apps]:
        log.add(login, "assign_app", f"already assigned: {label}", "skipped")

    # Extras: removed only with --prune (and --apply for the real write).
    for name in sorted(set(have_groups) - set(desired_groups)):
        gid = have_groups[name]["id"]
        if not prune:
            log.add(login, "remove_group",
                    f"extra group kept (--prune not set): {name}", "skipped")
            continue
        do_write(client, "delete", f"/api/v1/groups/{gid}/users/{uid}", None,
                 log, login, "remove_group", f"remove from group: {name}", apply)
    for label in sorted(set(have_apps) - set(desired_apps)):
        aid = have_apps[label]["id"]
        if not prune:
            log.add(login, "unassign_app",
                    f"extra app kept (--prune not set): {label}", "skipped")
            continue
        do_write(client, "delete", f"/api/v1/apps/{aid}/users/{uid}", None,
                 log, login, "unassign_app", f"unassign app: {label}", apply)
    return log.actions


def process_leaver(client: OktaClient, row: dict, apply: bool) -> list[dict]:
    log = ActionLog()
    login = (row.get("login") or "").strip()
    if not login:
        log.add("?", "deactivate", "row missing login", "error")
        return log.actions
    user = client.get_user_by_login(login)
    if user is None:
        log.add(login, "deactivate", "user not found", "error")
        return log.actions
    uid = user["id"]
    if user.get("status") == "ACTIVE":
        do_write(client, "post", f"/api/v1/users/{uid}/lifecycle/deactivate", None,
                 log, login, "deactivate", "deactivate user", apply)
    else:
        log.add(login, "deactivate",
                f"already {user.get('status', 'not active')}", "skipped")
    apps = current_apps(client, uid)
    groups = current_groups(client, uid)
    log.add(login, "remaining_apps",
            ", ".join(sorted(apps)) or "none", "info")
    log.add(login, "remaining_groups",
            ", ".join(sorted(groups)) or "none", "info")
    return log.actions


# ---- output ----

def print_table(actions: list[dict]):
    print(f"{'LOGIN':36} {'ACTION':16} {'STATUS':9} DETAIL")
    print("-" * 130)
    for a in actions:
        print(f"{(a['login'] or '')[:36]:36} {a['action'][:16]:16} "
              f"{a['status']:9} {(a['detail'] or '')[:70]}")


def main():
    p = argparse.ArgumentParser(
        description="Joiner/Mover/Leaver provisioning kit. Dry-run by default; "
                    "pass --apply to make changes.")
    p.add_argument("--mode", required=True, choices=["joiner", "mover", "leaver"],
                   help="JML mode to run")
    p.add_argument("--csv", required=True,
                   help="CSV with columns: login, firstName, lastName, "
                        "email (optional), groups (; separated), apps (; separated)")
    p.add_argument("--apply", action="store_true",
                   help="perform writes; without it, only report what would change")
    p.add_argument("--prune", action="store_true",
                   help="mover mode: also remove group/app assignments not in the CSV")
    p.add_argument("--limit", type=int, default=0,
                   help="only process N CSV rows (0 = all)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    actions: list[dict] = []
    for n, row in enumerate(rows, 1):
        if args.limit and n > args.limit:
            break
        try:
            if args.mode == "joiner":
                actions.extend(process_joiner(client, row, args.apply))
            elif args.mode == "mover":
                actions.extend(process_mover(client, row, args.apply, args.prune))
            else:
                actions.extend(process_leaver(client, row, args.apply))
        except OktaAuthError:
            raise
        except Exception as e:  # per-row failure must not abort the batch
            login = (row.get("login") or "?").strip()
            actions.append({"login": login, "action": args.mode,
                            "detail": f"{type(e).__name__}: {e}", "status": "error"})

    counts = {}
    for a in actions:
        counts[a["status"]] = counts.get(a["status"], 0) + 1
    summary = {"rows": len(rows[:args.limit] if args.limit else rows),
               "actions": len(actions),
               "changed_or_would_change": sum(
                   1 for a in actions if a["status"] in ("done", "dry-run")),
               **counts}

    if args.json:
        report = json.dumps({
            "mode": args.mode, "csv": args.csv, "apply": args.apply,
            "prune": args.prune, "summary": summary, "actions": actions,
        }, indent=2)
    else:
        print_table(actions)
        mode_word = "DRY RUN" if not args.apply else "APPLIED"
        report = (f"\n[{mode_word}] rows: {summary['rows']} | actions: {summary['actions']} | "
                  f"changed/would-change: {summary['changed_or_would_change']} | "
                  f"errors: {counts.get('error', 0)}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
