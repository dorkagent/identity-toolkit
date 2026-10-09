#!/usr/bin/env python3
"""Find dormant Okta accounts and, if asked, suspend or deactivate them.

An ACTIVE user is flagged when:
  DORMANT          lastLogin is older than --days
  NEVER_LOGGED_IN  there is no lastLogin and the account is older than --days

lastLogin is the last Okta sign-in, not the last use of any app.

Some accounts never sign in interactively and still matter: service accounts
that own API tokens, provisioning accounts, break-glass admins. Okta revokes a
user's API tokens when the user is deactivated, so sweeping those accounts can
break integrations, including the token this script runs on. Before acting the
script skips:
  - the user that owns the current API token (GET /api/v1/users/me)
  - owners of any active API token (GET /api/v1/api-tokens, super admin only)
  - every admin-role holder (GET /api/v1/iam/assignees/users)
  - logins or user IDs listed in --exclude-file, and members of --exclude-group

Nothing changes without --apply. The default action is suspend, which is
reversible; --action deactivate is the harder option. --limit caps how many
accounts are acted on, and --max aborts before any change if more accounts
than that would be touched.

Examples:
    python scripts/stale_account_sweeper.py
    python scripts/stale_account_sweeper.py --days 180 --output stale.csv
    python scripts/stale_account_sweeper.py --exclude-file keep.txt --exclude-group "Service Accounts"
    python scripts/stale_account_sweeper.py --apply --limit 10            # suspend 10
    python scripts/stale_account_sweeper.py --apply --action deactivate --max 50
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, parse_ts
from lib.okta_client import OktaClient, OktaError, OktaForbiddenError
from lib.output import emit, table

LIFECYCLE_PATH = {
    "suspend": "/api/v1/users/{id}/lifecycle/suspend",
    "deactivate": "/api/v1/users/{id}/lifecycle/deactivate",
}


def find_stale(users, days: int, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    rows = []
    for user in users:
        profile = user.get("profile") or {}
        last_login = parse_ts(user.get("lastLogin"))
        if last_login is not None:
            idle = (now - last_login).days
            category = "DORMANT"
        else:
            created = parse_ts(user.get("created"))
            if created is None:
                continue
            idle = (now - created).days
            category = "NEVER_LOGGED_IN"
        if idle < days:
            continue
        rows.append({
            "user_id": user.get("id"),
            "login": profile.get("login"),
            "name": f"{profile.get('firstName') or ''} {profile.get('lastName') or ''}".strip(),
            "last_login": user.get("lastLogin"),
            "days_idle": idle,
            "category": category,
            "action": "none",
            "skip_reason": "",
        })
    return rows


def load_exclude_file(path: str | None) -> set[str]:
    if not path:
        return set()
    with open(path, encoding="utf-8") as f:
        return {line.strip().lower() for line in f
                if line.strip() and not line.lstrip().startswith("#")}


def protected_accounts(client: OktaClient, exclude_groups: list[str]) -> dict[str, str]:
    """user id -> reason it must never be swept."""
    protected: dict[str, str] = {}

    me = client.get_current_user()
    if me:
        protected[me["id"]] = "owns the API token this script is using"

    try:
        for tok in client.list_api_tokens():
            if tok.get("userId"):
                protected.setdefault(tok["userId"], f"owns API token '{tok.get('name')}'")
    except OktaForbiddenError:
        print("warning: cannot list API tokens (needs super admin); only the "
              "current token's owner is protected", file=sys.stderr)

    try:
        for uid in client.list_role_assignee_user_ids():
            protected.setdefault(uid, "holds an admin role")
    except OktaForbiddenError:
        print("warning: cannot list admin role holders; admins are not "
              "auto-excluded", file=sys.stderr)

    for name in exclude_groups:
        group = next((g for g in client.list_groups(name)
                      if (g.get("profile") or {}).get("name") == name), None)
        if group is None:
            raise SystemExit(f"error: --exclude-group '{name}' not found")
        for m in client.list_group_members(group["id"]):
            protected.setdefault(m["id"], f"member of excluded group '{name}'")
    return protected


def apply_exclusions(rows: list[dict], protected: dict[str, str],
                     excluded: set[str]) -> None:
    for r in rows:
        if r["user_id"] in protected:
            r["skip_reason"] = protected[r["user_id"]]
        elif (r["login"] or "").lower() in excluded or r["user_id"].lower() in excluded:
            r["skip_reason"] = "listed in --exclude-file"


def act(client: OktaClient, rows: list[dict], action: str, apply: bool,
        limit: int) -> None:
    """Suspend or deactivate the candidates, one at a time, recording each result."""
    done = 0
    for r in rows:
        if r["skip_reason"]:
            r["action"] = "skipped"
            continue
        if limit and done >= limit:
            r["action"] = "not processed (--limit reached)"
            continue
        done += 1
        if not apply:
            r["action"] = f"would {action}"
            continue
        try:
            client.post(LIFECYCLE_PATH[action].format(id=r["user_id"]))
            r["action"] = "suspended" if action == "suspend" else "deactivated"
        except OktaError as e:
            r["action"] = f"failed: {e}"


def render(rows: list[dict], summary: dict) -> str:
    body = table(
        [("LOGIN", 38), ("LAST LOGIN", 20), ("DAYS", 5), ("CATEGORY", 15), ("ACTION", 0)],
        [[r["login"], r["last_login"] or "never", r["days_idle"], r["category"],
          r["action"] + (f" ({r['skip_reason']})" if r["skip_reason"] else "")]
         for r in rows])
    return (f"{body}\n\n{'APPLIED' if summary['applied'] else 'DRY RUN'}: "
            f"{summary['stale_users']} stale, {summary['skipped']} protected, "
            f"{summary['acted_or_would_act']} {summary['action']} candidates")


def main(argv=None):
    p = argparse.ArgumentParser(description="Find dormant Okta users; optionally "
                                "suspend or deactivate them (dry run by default).")
    p.add_argument("--days", type=int, default=90, help="idle threshold in days (default 90)")
    p.add_argument("--action", choices=sorted(LIFECYCLE_PATH), default="suspend",
                   help="what --apply does (default suspend, which is reversible)")
    p.add_argument("--apply", action="store_true", help="make the changes")
    p.add_argument("--limit", type=int, default=0,
                   help="act on at most N accounts (0 = no cap)")
    p.add_argument("--max", type=int, default=25,
                   help="refuse to apply if more than N accounts would change (default 25)")
    p.add_argument("--exclude-file", help="file of logins or user IDs to never touch, one per line")
    p.add_argument("--exclude-group", action="append", default=[],
                   help="group name whose members are never touched (repeatable)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    client = connect()
    rows = find_stale(client.list_users(status="ACTIVE"), args.days)
    apply_exclusions(rows, protected_accounts(client, args.exclude_group),
                     load_exclude_file(args.exclude_file))

    candidates = [r for r in rows if not r["skip_reason"]]
    to_change = min(len(candidates), args.limit) if args.limit else len(candidates)
    if args.apply and to_change > args.max:
        raise SystemExit(f"error: {to_change} accounts would be changed, above --max "
                         f"{args.max}. Narrow it with --limit or raise --max.")

    act(client, rows, args.action, args.apply, args.limit)

    summary = {"threshold_days": args.days, "applied": args.apply,
               "action": args.action, "stale_users": len(rows),
               "skipped": len(rows) - len(candidates), "acted_or_would_act": to_change}
    emit(report={"summary": summary, "users": rows}, text=render(rows, summary),
         as_json=args.json, output=args.output, csv_rows=rows,
         csv_fields=["login", "name", "last_login", "days_idle", "category",
                     "action", "skip_reason"])


if __name__ == "__main__":
    main()
