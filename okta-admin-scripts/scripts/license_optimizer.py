#!/usr/bin/env python3
"""Rough per-app license waste estimate (read-only).

Unused apps: one bounded pass over the System Log for user.authentication.sso
events in the last --lookback-days (at most 90, which is all Okta keeps),
counting sign-ins per app. Apps with assignments but no sign-ins in the window
are listed with seats x --cost-default (or the per-app price from
--cost-file, a JSON map of app label to monthly cost per seat).

This is app-level only. Apps that never emit user.authentication.sso
(bookmark apps, provisioning-only apps, some OIDC flows) will show as unused,
so check before reclaiming anything. Okta's Application Usage report covers
the same ground per user.

Shared mailboxes: ACTIVE users that share a profile.email are listed too.
Logins are unique in Okta, so there is no duplicate-login check.

Examples:
    python scripts/license_optimizer.py
    python scripts/license_optimizer.py --lookback-days 30 --cost-file costs.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, log_window
from lib.okta_client import OktaClient
from lib.output import emit, table

# user.session.start targets the user, not an app, so only SSO events count.
LOGIN_EVENTS_FILTER = 'eventType eq "user.authentication.sso"'


def tally_logins(client: OktaClient, app_ids: set, since: str, until: str) -> dict:
    """Count SSO events per app id in one pass over the System Log."""
    logins = {aid: 0 for aid in app_ids}
    for event in client.list_logs(filter=LOGIN_EVENTS_FILTER, since=since, until=until):
        for target in event.get("target") or []:
            if target.get("id") in logins:
                logins[target["id"]] += 1
    return logins


def find_shared_emails(client: OktaClient) -> list[dict]:
    by_email: dict[str, list] = {}
    for user in client.list_users(status="ACTIVE"):
        profile = user.get("profile") or {}
        email = (profile.get("email") or "").lower()
        if email:
            by_email.setdefault(email, []).append(profile.get("login"))
    return [{"email": k, "logins": v} for k, v in sorted(by_email.items()) if len(v) > 1]


def optimize(client: OktaClient, lookback_days: int, costs: dict,
             cost_default: float, limit: int = 0):
    since, until, _ = log_window(lookback_days)
    apps = [a for a in client.list_apps() if a.get("status") != "INACTIVE"]
    if limit:
        apps = apps[:limit]
    logins = tally_logins(client, {a["id"] for a in apps}, since, until)
    waste = []
    for app in apps:
        if logins.get(app["id"], 0) > 0:
            continue
        seats = sum(1 for _ in client.list_app_users(app["id"]))
        if seats == 0:
            continue
        cost = float(costs.get(app.get("label"), cost_default))
        waste.append({"app": app.get("label"), "app_id": app["id"],
                      "unused_seats": seats, "cost_per_seat": cost,
                      "est_monthly_waste": round(seats * cost, 2)})
    waste.sort(key=lambda w: w["est_monthly_waste"], reverse=True)
    return waste, find_shared_emails(client), since


def render(waste: list, shared: list, since: str) -> str:
    lines = [f"Apps with assignments and no SSO sign-ins since {since}:",
             table([("APP", 40), ("SEATS", 6), ("$/SEAT", 8), ("$/MONTH", 0)],
                   [[w["app"], w["unused_seats"], f"{w['cost_per_seat']:.2f}",
                     f"{w['est_monthly_waste']:.2f}"] for w in waste])]
    total = sum(w["est_monthly_waste"] for w in waste)
    lines.append(f"\nEstimated monthly waste: ${total:,.2f} across {len(waste)} apps")
    lines.append("\nActive users sharing an email address:")
    lines += [f"  {d['email']}: {', '.join(d['logins'])}" for d in shared] or ["  none"]
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description="Estimate license waste from apps with "
                                "no recent SSO sign-ins (read-only).")
    p.add_argument("--lookback-days", type=int, default=90,
                   help="days of System Log to read (default 90, the most Okta keeps)")
    p.add_argument("--limit", type=int, default=0, help="only check the first N apps")
    p.add_argument("--cost-file", help="JSON map of app label to monthly cost per seat")
    p.add_argument("--cost-default", type=float, default=10,
                   help="monthly cost per seat when not in --cost-file (default 10)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    costs = {}
    if args.cost_file:
        with open(args.cost_file, encoding="utf-8") as f:
            costs = json.load(f)
    if args.lookback_days > 90:
        print("note: the System Log keeps 90 days; using 90", file=sys.stderr)

    waste, shared, since = optimize(connect(), args.lookback_days, costs,
                                    args.cost_default, args.limit)
    summary = {"since": since, "unused_apps": len(waste),
               "est_monthly_waste": round(sum(w["est_monthly_waste"] for w in waste), 2),
               "shared_emails": len(shared)}
    emit(report={"summary": summary, "unused_apps": waste, "shared_emails": shared},
         text=render(waste, shared, since), as_json=args.json,
         output=args.output, csv_rows=waste)


if __name__ == "__main__":
    main()
