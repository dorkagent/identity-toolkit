#!/usr/bin/env python3
"""Stale account sweeper (DHQ-82).

Finds ACTIVE users whose accounts look dormant:

  - DORMANT: lastLogin older than --days (default 90).
  - NEVER_LOGGED_IN: no lastLogin at all and created older than --days.

DRY-RUN BY DEFAULT. Actual deactivation (POST
/api/v1/users/{id}/lifecycle/deactivate) only happens when BOTH --disable
AND --confirm are passed.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/stale_account_sweeper.py
    python scripts/python/stale_account_sweeper.py --days 180
    python scripts/python/stale_account_sweeper.py --json --output stale.json
    python scripts/python/stale_account_sweeper.py --output stale.csv
    python scripts/python/stale_account_sweeper.py --disable --confirm   # live run
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Okta timestamps are ISO8601, e.g. 2026-09-01T12:34:56.000Z
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sweep(client: OktaClient, days: int, progress_every: int = 100):
    now = datetime.now(timezone.utc)
    rows = []
    for n, user in enumerate(client.list_users(status="ACTIVE"), 1):
        profile = user.get("profile", {})
        login = profile.get("login")
        last_login = parse_ts(user.get("lastLogin"))
        if last_login is not None:
            dormant_days = (now - last_login).days
            if dormant_days < days:
                continue
            category = "DORMANT"
        else:
            created = parse_ts(user.get("created"))
            dormant_days = (now - created).days if created else None
            if dormant_days is None or dormant_days < days:
                continue
            category = "NEVER_LOGGED_IN"
        rows.append({
            "login": login,
            "name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            "last_login": user.get("lastLogin"),
            "days_dormant": dormant_days,
            "category": category,
            "user_id": user.get("id"),
            "action": "would deactivate",
        })
        if n % progress_every == 0:
            print(f"... scanned {n} users", file=sys.stderr)
    return rows


def deactivate(client: OktaClient, rows: list):
    for r in rows:
        client.post(f"/api/v1/users/{r['user_id']}/lifecycle/deactivate")
        r["action"] = "deactivated"


def print_table(rows: list):
    print(f"{'LOGIN':40} {'NAME':28} {'LAST LOGIN':20} {'DAYS':>5} "
          f"{'CATEGORY':15} ACTION")
    print("-" * 140)
    for r in rows:
        print(f"{(r['login'] or '')[:40]:40} {(r['name'] or '')[:28]:28} "
              f"{(r['last_login'] or 'never')[:20]:20} "
              f"{r['days_dormant'] if r['days_dormant'] is not None else '?':>5} "
              f"{r['category']:15} {r['action']}")


def to_csv(rows: list) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=[
        "login", "name", "last_login", "days_dormant", "category", "action"])
    w.writeheader()
    for r in rows:
        w.writerow({k: r[k] for k in w.fieldnames})
    return buf.getvalue()


def main():
    p = argparse.ArgumentParser(
        description="Find dormant ACTIVE users. DRY-RUN by default; "
                    "deactivation requires BOTH --disable AND --confirm.")
    p.add_argument("--days", type=int, default=90,
                   help="inactivity threshold in days (default 90)")
    p.add_argument("--disable", action="store_true",
                   help="enable deactivation (requires --confirm too)")
    p.add_argument("--confirm", action="store_true",
                   help="second confirmation required for live deactivation")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None,
                   help="write report to file (.csv extension writes CSV)")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    rows = sweep(client, days=args.days)

    live = args.disable and args.confirm
    if live:
        deactivate(client, rows)
    elif args.disable and not args.confirm:
        print("dry-run: --disable given without --confirm; no accounts touched",
              file=sys.stderr)

    for r in rows:
        del r["user_id"]

    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    summary = {"threshold_days": args.days, "dry_run": not live,
               "stale_users": len(rows), **counts}

    if args.json:
        report = json.dumps({"summary": summary, "users": rows}, indent=2)
    elif args.output and args.output.endswith(".csv"):
        report = to_csv(rows)
    else:
        print_table(rows)
        report_lines = [
            "",
            f"{'DRY RUN' if not live else 'LIVE'}: {summary['stale_users']} stale users | "
            f"dormant: {counts.get('DORMANT', 0)} | "
            f"never logged in: {counts.get('NEVER_LOGGED_IN', 0)}",
        ]
        report = "\n".join(report_lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if (args.json or args.output.endswith(".csv"))
                    else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
