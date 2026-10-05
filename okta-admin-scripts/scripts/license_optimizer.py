#!/usr/bin/env python3
"""License optimizer (DHQ-83). READ-ONLY.

Two views of license waste:

  1. UNUSED APP ASSIGNMENTS: single pass over the System Log
     (eventType eq "user.authentication.sso" or eventType eq "user.session.start")
     for the last --lookback-days (default 90). Login events are tallied per
     app by matching event.target ids against known app ids. Apps with zero
     logins but >0 assignments are waste candidates.
  2. DUPLICATE IDENTITIES: ACTIVE users grouped by lowercased login and by
     lowercased profile.email; groups of 2+ are reported.

Waste estimate: --cost-file JSON {appLabel: monthlyCostPerSeat} overrides the
--cost-default (default $10) per-seat monthly cost. Waste per app =
unused seats * cost/seat. Results are ranked by estimated monthly waste.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/license_optimizer.py
    python scripts/python/license_optimizer.py --lookback-days 180 --limit 10
    python scripts/python/license_optimizer.py --cost-file costs.json
    python scripts/python/license_optimizer.py --json --output waste.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError

LOGIN_EVENTS_FILTER = (
    'eventType eq "user.authentication.sso" '
    'or eventType eq "user.session.start"'
)


def tally_logins(client: OktaClient, app_ids: set, since: str,
                 progress_every: int = 5000):
    """Single pass over the System Log; count login events per app id."""
    logins = {aid: 0 for aid in app_ids}
    n = 0
    for event in client.list_logs(filter=LOGIN_EVENTS_FILTER, since=since):
        n += 1
        for target in event.get("target", []) or []:
            tid = target.get("id")
            if tid in logins:
                logins[tid] += 1
        if n % progress_every == 0:
            print(f"... scanned {n} log events", file=sys.stderr)
    return logins


def find_duplicates(client: OktaClient, progress_every: int = 100):
    by_login: dict[str, list] = {}
    by_email: dict[str, list] = {}
    for n, user in enumerate(client.list_users(status="ACTIVE"), 1):
        profile = user.get("profile", {})
        login = (profile.get("login") or "").lower()
        email = (profile.get("email") or "").lower()
        if login:
            by_login.setdefault(login, []).append(profile.get("login"))
        if email:
            by_email.setdefault(email, []).append(profile.get("login"))
        if n % progress_every == 0:
            print(f"... scanned {n} users", file=sys.stderr)
    dupes = []
    for key, members in by_login.items():
        if len(members) >= 2:
            dupes.append({"field": "login", "value": key, "logins": members})
    for key, members in by_email.items():
        if len(members) >= 2:
            dupes.append({"field": "email", "value": key, "logins": members})
    return dupes


def optimize(client: OktaClient, lookback_days: int, costs: dict,
             cost_default: float, limit: int = 0, progress_every: int = 25):
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    apps = list(client.list_apps())
    app_ids = {a.get("id") for a in apps if a.get("id")}
    logins = tally_logins(client, app_ids, since=cutoff)

    waste = []
    for n, app in enumerate(apps, 1):
        if limit and n > limit:
            break
        app_id = app.get("id")
        label = app.get("label")
        if logins.get(app_id, 0) > 0:
            continue
        assignments = sum(1 for _ in client.list_app_users(app_id))
        if assignments == 0:
            continue
        cost = costs.get(label, cost_default)
        waste.append({
            "app": label,
            "app_id": app_id,
            "logins_in_window": 0,
            "unused_seats": assignments,
            "cost_per_seat": cost,
            "est_monthly_waste": round(assignments * cost, 2),
        })
        if n % progress_every == 0:
            print(f"... checked {n} apps", file=sys.stderr)
    waste.sort(key=lambda w: w["est_monthly_waste"], reverse=True)

    duplicates = find_duplicates(client)
    return waste, duplicates, cutoff


def print_tables(waste: list, duplicates: list, cutoff: str,
                 lookback_days: int):
    print(f"Apps with zero login events since {cutoff} ({lookback_days}d lookback):")
    print(f"{'APP':40} {'UNUSED SEATS':>12} {'COST/SEAT':>10} {'EST MONTHLY WASTE':>18}")
    print("-" * 84)
    for w in waste:
        print(f"{(w['app'] or '')[:40]:40} {w['unused_seats']:>12} "
              f"${w['cost_per_seat']:>9.2f} ${w['est_monthly_waste']:>17.2f}")
    total = sum(w["est_monthly_waste"] for w in waste)
    print(f"\nEstimated total monthly waste: ${total:,.2f} across {len(waste)} apps")

    print("\nDuplicate identities (ACTIVE users, groups of 2+):")
    if not duplicates:
        print("  none found")
    for d in duplicates:
        print(f"  {d['field']}={d['value']}: {', '.join(d['logins'])}")


def main():
    p = argparse.ArgumentParser(
        description="Find unused app assignments and duplicate identities. READ-ONLY.")
    p.add_argument("--lookback-days", type=int, default=90,
                   help="System Log lookback window in days (default 90)")
    p.add_argument("--limit", type=int, default=0,
                   help="only check N apps (0 = all)")
    p.add_argument("--cost-file", default=None,
                   help="JSON file mapping app label -> monthly cost per seat")
    p.add_argument("--cost-default", type=float, default=10,
                   help="default monthly cost per seat (default 10)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    costs = {}
    if args.cost_file:
        with open(args.cost_file, encoding="utf-8") as f:
            costs = json.load(f)

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    waste, duplicates, cutoff = optimize(
        client, lookback_days=args.lookback_days, costs=costs,
        cost_default=args.cost_default, limit=args.limit)

    total = round(sum(w["est_monthly_waste"] for w in waste), 2)
    summary = {"lookback_days": args.lookback_days, "since": cutoff,
               "waste_apps": len(waste), "est_total_monthly_waste": total,
               "duplicate_groups": len(duplicates)}

    if args.json:
        report = json.dumps({"summary": summary, "waste": waste,
                             "duplicates": duplicates}, indent=2)
    else:
        print_tables(waste, duplicates, cutoff, args.lookback_days)
        report_lines = [
            "",
            f"Waste apps: {summary['waste_apps']} | "
            f"est monthly waste: ${total:,.2f} | "
            f"duplicate groups: {summary['duplicate_groups']}",
        ]
        report = "\n".join(report_lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
