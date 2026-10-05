#!/usr/bin/env python3
"""Break-glass account monitor (READ-ONLY).

Watches the Okta System Log for sign-in activity by break-glass (emergency
access) accounts and classifies each event as SUCCESS or FAILED so misuse is
immediately visible. Break-glass accounts are passed on the command line --
never hardcoded.

One-shot mode (default): scans the last N hours of logs and prints a table.
Watch mode (--watch): polls forever and alerts the moment a new matching
event appears.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/break_glass_monitor.py --accounts "breakglass1@example.com,breakglass2@example.com"
    python scripts/python/break_glass_monitor.py --accounts "breakglass1@example.com" --lookback-hours 72
    python scripts/python/break_glass_monitor.py --accounts "breakglass1@example.com" --watch --interval 120
    python scripts/python/break_glass_monitor.py --accounts "breakglass1@example.com" --json --output alerts.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError

LOG_FILTER = (
    'eventType eq "user.session.start" '
    'or eventType eq "policy.evaluate_sign_on"'
)


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def classify(event: dict) -> str:
    """user.session.start = SUCCESS; failed sign-on evaluation = FAILED;
    passed sign-on evaluation = ALLOWED (policy passed, no session started)."""
    etype = event.get("eventType", "")
    if etype == "user.session.start":
        return "SUCCESS"
    if etype == "policy.evaluate_sign_on":
        outcome = event.get("outcome") or {}
        return "FAILED" if outcome.get("result") == "FAILURE" else "ALLOWED"
    return "OTHER"


def geo_of(event: dict) -> tuple[str, str]:
    client = event.get("client") or {}
    ip = client.get("ipAddress") or "-"
    geo = client.get("geographicalContext") or {}
    location = ", ".join(
        p for p in (geo.get("city"), geo.get("country")) if p
    ) or "-"
    return ip, location


def match_event(event: dict, by_id: dict, by_login: dict) -> str | None:
    """Return the break-glass login if this event belongs to one, else None."""
    actor = event.get("actor") or {}
    aid = actor.get("id")
    if aid and aid in by_id:
        return by_id[aid]
    alogin = actor.get("login") or actor.get("displayName")
    if alogin and alogin in by_login:
        return by_login[alogin]
    return None


def row_of(event: dict, account: str) -> dict:
    ip, location = geo_of(event)
    return {
        "time": event.get("published", "?"),
        "account": account,
        "result": classify(event),
        "ip": ip,
        "location": location,
        "event": event.get("eventType", "?"),
    }


def print_header():
    print(f"{'TIME':22} {'ACCOUNT':32} {'RESULT':9} {'IP':17} {'LOCATION':28} EVENT")
    print("-" * 140)


def print_row(r: dict):
    ts = (r["time"] or "")[:19].replace("T", " ")
    print(f"{ts:22} {(r['account'] or '')[:32]:32} {r['result']:9} "
          f"{(r['ip'] or '')[:17]:17} {(r['location'] or '')[:28]:28} {r['event']}")


def print_table(rows: list):
    print_header()
    for r in rows:
        print_row(r)


def scan(client: OktaClient, since: str, by_id: dict, by_login: dict,
         limit: int = 0) -> list:
    rows = []
    for event in client.list_logs(filter=LOG_FILTER, since=since):
        account = match_event(event, by_id, by_login)
        if account is None:
            continue
        rows.append(row_of(event, account))
        if limit and len(rows) >= limit:
            break
    return rows


def run_watch(client: OktaClient, by_id: dict, by_login: dict, interval: int):
    last_seen = utc_iso(datetime.now(timezone.utc))
    print(f"watching break-glass accounts "
          f"({', '.join(sorted(by_login))}); polling every {interval}s "
          f"(Ctrl-C to stop)", file=sys.stderr)
    try:
        while True:
            for event in client.list_logs(filter=LOG_FILTER, since=last_seen):
                published = event.get("published") or ""
                if published <= last_seen:
                    continue
                last_seen = max(last_seen, published)
                account = match_event(event, by_id, by_login)
                if account is None:
                    continue
                r = row_of(event, account)
                flag = " !!!" if r["result"] == "FAILED" else ""
                print(f"[{r['time']}] ALERT{flag} account={r['account']} "
                      f"result={r['result']} ip={r['ip']} "
                      f"location={r['location']} event={r['event']}",
                      flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatch stopped", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(
        description="Monitor break-glass Okta accounts via the System Log (read-only).")
    p.add_argument("--accounts", required=True,
                   help='comma-separated break-glass logins, e.g. "bg1@example.com,bg2@example.com"')
    p.add_argument("--lookback-hours", type=int, default=24,
                   help="hours of history to scan in one-shot mode (default 24)")
    p.add_argument("--watch", action="store_true",
                   help="poll continuously for new events instead of one scan")
    p.add_argument("--interval", type=int, default=300,
                   help="poll interval in seconds for --watch (default 300)")
    p.add_argument("--limit", type=int, default=0,
                   help="cap matching events processed in one-shot mode (0 = all)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    logins = [a.strip() for a in args.accounts.split(",") if a.strip()]
    if not logins:
        print("error: --accounts must list at least one login", file=sys.stderr)
        sys.exit(2)

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    # Resolve logins to user ids so actor.id matches work too.
    by_id, by_login, unknown = {}, {}, []
    for login in logins:
        user = client.get_user_by_login(login)
        if user is None:
            unknown.append(login)
        else:
            by_id[user["id"]] = login
            by_login[login] = login
    for login in unknown:
        print(f"warning: no Okta user found for {login}; "
              f"actor-login matching will still be attempted", file=sys.stderr)
        by_login[login] = login

    if args.watch:
        run_watch(client, by_id, by_login, args.interval)
        return

    cutoff = utc_iso(datetime.now(timezone.utc) - timedelta(hours=args.lookback_hours))
    rows = scan(client, cutoff, by_id, by_login, limit=args.limit)

    counts = {}
    for r in rows:
        counts[r["result"]] = counts.get(r["result"], 0) + 1

    if args.json:
        report = json.dumps({
            "accounts": logins,
            "lookback_hours": args.lookback_hours,
            "cutoff": cutoff,
            "summary": {"events": len(rows), **counts},
            "events": rows,
        }, indent=2)
    else:
        print_table(rows)
        summary = (f"\nEvents: {len(rows)} | SUCCESS: {counts.get('SUCCESS', 0)} | "
                   f"FAILED: {counts.get('FAILED', 0)} | "
                   f"ALLOWED: {counts.get('ALLOWED', 0)}")
        report = summary

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
