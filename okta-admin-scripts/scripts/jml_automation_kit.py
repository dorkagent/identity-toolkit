#!/usr/bin/env python3
"""Joiner / mover / leaver changes driven by a CSV file.

CSV columns: login, firstName, lastName, email (optional, defaults to login),
groups (names separated by ;), apps (app labels separated by ;).

    joiner  create the user (staged, activate=false) or fix the profile of an
            existing one, then add the listed groups and apps
    mover   fix the profile, add missing groups and apps; with --prune also
            remove groups and apps that are not in the row
    leaver  deactivate the user and list what is still assigned

Nothing changes without --apply. Running the same file twice is safe: state
that is already correct is reported as skipped.

Profile changes use POST /api/v1/users/{id}, which only touches the fields
sent. (PUT replaces the whole profile and would wipe every attribute not in
the CSV.)

--prune is deliberately narrow. It only removes memberships of OKTA_GROUP
groups, never BUILT_IN (Everyone) or APP_GROUP (imported from AD/LDAP), and
only direct app assignments, never ones inherited from a group. It also refuses
to prune a row whose groups or apps cell is empty, so a blank cell can't strip
someone's access. Memberships that a group rule adds will come back on the next
rule evaluation; fix the attribute that drives the rule instead.

Examples:
    python scripts/jml_automation_kit.py --mode joiner --csv hires.csv
    python scripts/jml_automation_kit.py --mode joiner --csv hires.csv --apply
    python scripts/jml_automation_kit.py --mode mover --csv moves.csv --apply --prune
    python scripts/jml_automation_kit.py --mode leaver --csv exits.csv --apply --output leavers.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect
from lib.okta_client import OktaAuthError, OktaClient, OktaError, OktaNotFoundError, quote_filter_value
from lib.output import emit, table

PROFILE_FIELDS = ("firstName", "lastName", "email", "login")


def parse_list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(";") if v.strip()]


def desired_profile(row: dict) -> dict:
    login = (row.get("login") or "").strip()
    return {
        "firstName": (row.get("firstName") or "").strip(),
        "lastName": (row.get("lastName") or "").strip(),
        "email": (row.get("email") or "").strip() or login,
        "login": login,
    }


class Plan:
    """Collects what was done, or would be done, for one run."""

    def __init__(self, client: OktaClient, apply: bool):
        self.client = client
        self.apply = apply
        self.actions: list[dict] = []
        self._groups: dict[str, dict | None] = {}
        self._apps: dict[str, dict | None] = {}

    def log(self, login, action, detail, status):
        self.actions.append({"login": login, "action": action,
                             "detail": detail, "status": status})

    def write(self, login, action, detail, method, path, data=None):
        if not self.apply:
            self.log(login, action, f"would {detail}", "dry-run")
            return None
        result = getattr(self.client, method)(path, data)
        self.log(login, action, detail, "done")
        return result

    def find_group(self, name: str) -> dict | None:
        if name not in self._groups:
            self._groups[name] = next(
                (g for g in self.client.list_groups(name)
                 if (g.get("profile") or {}).get("name") == name), None)
        return self._groups[name]

    def find_app(self, label: str) -> dict | None:
        if label not in self._apps:
            self._apps[label] = next(
                (a for a in self.client.paged_get("/api/v1/apps", {"q": label})
                 if a.get("label") == label), None)
        return self._apps[label]


def current_groups(client: OktaClient, uid: str) -> dict[str, dict]:
    return {(g.get("profile") or {}).get("name"): g
            for g in client.list_user_groups(uid)
            if (g.get("profile") or {}).get("name")}


def current_apps(client: OktaClient, uid: str) -> dict[str, dict]:
    flt = f'user.id eq "{quote_filter_value(uid)}"'
    return {a["label"]: a for a in client.paged_get("/api/v1/apps", {"filter": flt})
            if a.get("label")}


def sync_profile(plan: Plan, login: str, user: dict, row: dict) -> None:
    profile = user.get("profile") or {}
    want = desired_profile(row)
    changed = {k: v for k, v in want.items() if profile.get(k) != v}
    if not changed:
        plan.log(login, "update_profile", "profile already matches", "skipped")
        return
    detail = "update " + ", ".join(f"{k}={v}" for k, v in changed.items())
    # POST is a partial update: only the changed keys are sent.
    plan.write(login, "update_profile", detail, "post",
               f"/api/v1/users/{user['id']}", {"profile": changed})


def add_groups(plan: Plan, login: str, uid: str | None, names: list[str],
               have: dict[str, dict]) -> None:
    for name in names:
        if name in have:
            plan.log(login, "add_group", f"already a member of {name}", "skipped")
            continue
        group = plan.find_group(name)
        if group is None:
            plan.log(login, "add_group", f"group not found: {name}", "error")
        elif group.get("type") != "OKTA_GROUP":
            plan.log(login, "add_group",
                     f"{name} is {group.get('type')}; Okta only allows changes to "
                     "OKTA_GROUP memberships", "error")
        elif uid is None:
            plan.log(login, "add_group", f"would add to {name} after creation", "dry-run")
        else:
            plan.write(login, "add_group", f"add to {name}", "put",
                       f"/api/v1/groups/{group['id']}/users/{uid}")


def add_apps(plan: Plan, login: str, uid: str | None, labels: list[str],
             have: dict[str, dict]) -> None:
    for label in labels:
        if label in have:
            plan.log(login, "assign_app", f"already assigned {label}", "skipped")
            continue
        app = plan.find_app(label)
        if app is None:
            plan.log(login, "assign_app", f"app not found: {label}", "error")
        elif uid is None:
            plan.log(login, "assign_app", f"would assign {label} after creation", "dry-run")
        else:
            plan.write(login, "assign_app", f"assign {label}", "post",
                       f"/api/v1/apps/{app['id']}/users", {"id": uid})


def prune(plan: Plan, login: str, uid: str, row: dict,
          have_groups: dict[str, dict], have_apps: dict[str, dict]) -> None:
    want_groups = set(parse_list(row.get("groups")))
    want_apps = set(parse_list(row.get("apps")))

    if not want_groups:
        plan.log(login, "remove_group", "groups cell is empty; not pruning groups", "skipped")
    else:
        for name in sorted(set(have_groups) - want_groups):
            g = have_groups[name]
            if g.get("type") != "OKTA_GROUP":
                plan.log(login, "remove_group",
                         f"kept {name}: {g.get('type')} membership is not managed here",
                         "skipped")
                continue
            plan.write(login, "remove_group", f"remove from {name}", "delete",
                       f"/api/v1/groups/{g['id']}/users/{uid}")

    if not want_apps:
        plan.log(login, "unassign_app", "apps cell is empty; not pruning apps", "skipped")
        return
    for label in sorted(set(have_apps) - want_apps):
        aid = have_apps[label]["id"]
        try:
            scope = (plan.client.get(f"/api/v1/apps/{aid}/users/{uid}") or {}).get("scope")
        except OktaNotFoundError:
            scope = None
        if scope != "USER":
            plan.log(login, "unassign_app",
                     f"kept {label}: assigned through a group (scope {scope})", "skipped")
            continue
        plan.write(login, "unassign_app", f"unassign {label}", "delete",
                   f"/api/v1/apps/{aid}/users/{uid}")


def process_joiner(plan: Plan, row: dict) -> None:
    login = desired_profile(row)["login"]
    user = plan.client.get_user_by_login(login)
    if user is None:
        created = plan.write(login, "create_user", "create user (staged, activate=false)",
                             "post", "/api/v1/users?activate=false",
                             {"profile": desired_profile(row)})
        uid = (created or {}).get("id")
        add_groups(plan, login, uid, parse_list(row.get("groups")), {})
        add_apps(plan, login, uid, parse_list(row.get("apps")), {})
        return
    sync_profile(plan, login, user, row)
    add_groups(plan, login, user["id"], parse_list(row.get("groups")),
               current_groups(plan.client, user["id"]))
    add_apps(plan, login, user["id"], parse_list(row.get("apps")),
             current_apps(plan.client, user["id"]))


def process_mover(plan: Plan, row: dict, do_prune: bool) -> None:
    login = desired_profile(row)["login"]
    user = plan.client.get_user_by_login(login)
    if user is None:
        plan.log(login, "update_profile", "user not found", "error")
        return
    uid = user["id"]
    sync_profile(plan, login, user, row)
    have_groups = current_groups(plan.client, uid)
    have_apps = current_apps(plan.client, uid)
    add_groups(plan, login, uid, parse_list(row.get("groups")), have_groups)
    add_apps(plan, login, uid, parse_list(row.get("apps")), have_apps)
    if do_prune:
        prune(plan, login, uid, row, have_groups, have_apps)
    else:
        extra_g = sorted(set(have_groups) - set(parse_list(row.get("groups"))))
        extra_a = sorted(set(have_apps) - set(parse_list(row.get("apps"))))
        if extra_g or extra_a:
            plan.log(login, "extras", "not in CSV, kept (no --prune): "
                     + ", ".join(extra_g + extra_a), "info")


def process_leaver(plan: Plan, row: dict) -> None:
    login = desired_profile(row)["login"]
    user = plan.client.get_user_by_login(login)
    if user is None:
        plan.log(login, "deactivate", "user not found", "error")
        return
    uid = user["id"]
    if user.get("status") in ("DEPROVISIONED",):
        plan.log(login, "deactivate", "already deactivated", "skipped")
    else:
        plan.write(login, "deactivate", "deactivate user", "post",
                   f"/api/v1/users/{uid}/lifecycle/deactivate")
    plan.log(login, "remaining_apps", ", ".join(sorted(current_apps(plan.client, uid))) or "none", "info")
    plan.log(login, "remaining_groups", ", ".join(sorted(current_groups(plan.client, uid))) or "none", "info")


def run(client: OktaClient, rows: list[dict], mode: str, apply: bool,
        do_prune: bool) -> list[dict]:
    plan = Plan(client, apply)
    for row in rows:
        login = (row.get("login") or "").strip()
        if not login:
            plan.log("?", mode, "row has no login", "error")
            continue
        try:
            if mode == "joiner":
                process_joiner(plan, row)
            elif mode == "mover":
                process_mover(plan, row, do_prune)
            else:
                process_leaver(plan, row)
        except OktaAuthError:
            raise  # bad credentials will fail every row; stop now
        except OktaError as e:
            # Includes 403s on a single user or group: record and move on.
            plan.log(login, mode, f"{type(e).__name__}: {e}", "error")
    return plan.actions


def main(argv=None):
    p = argparse.ArgumentParser(description="CSV-driven joiner/mover/leaver changes "
                                "(dry run unless --apply).")
    p.add_argument("--mode", required=True, choices=["joiner", "mover", "leaver"])
    p.add_argument("--csv", required=True, help="input CSV (see --help text above)")
    p.add_argument("--apply", action="store_true", help="make the changes")
    p.add_argument("--prune", action="store_true",
                   help="mover: also remove groups/apps not listed in the row")
    p.add_argument("--limit", type=int, default=0, help="only process the first N rows")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if args.limit:
        rows = rows[:args.limit]

    client = connect()
    actions = run(client, rows, args.mode, args.apply, args.prune)

    counts: dict[str, int] = {}
    for a in actions:
        counts[a["status"]] = counts.get(a["status"], 0) + 1
    summary = {"mode": args.mode, "applied": args.apply, "prune": args.prune,
               "rows": len(rows), **counts}
    text = table([("LOGIN", 34), ("ACTION", 16), ("STATUS", 8), ("DETAIL", 0)],
                 [[a["login"], a["action"], a["status"], a["detail"]] for a in actions])
    text += (f"\n\n{'APPLIED' if args.apply else 'DRY RUN'}: {len(rows)} rows, "
             f"{counts.get('done', 0) + counts.get('dry-run', 0)} changes, "
             f"{counts.get('error', 0)} errors")
    emit(report={"summary": summary, "actions": actions}, text=text,
         as_json=args.json, output=args.output, csv_rows=actions,
         csv_fields=["login", "action", "status", "detail"])


if __name__ == "__main__":
    main()
