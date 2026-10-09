#!/usr/bin/env python3
"""Report sign-in activity on break-glass (emergency admin) accounts.

Pass the accounts with --accounts; nothing is hardcoded. The script reads
these System Log events and keeps the ones where the actor is one of them:

    user.session.start              sign-in to Okta
    user.authentication.auth_via_mfa  MFA verification
    user.session.access_admin_app   opened the Admin Console
    policy.evaluate_sign_on         sign-on policy decision

Each event is labelled by its own outcome.result (SUCCESS, FAILURE, ALLOW,
CHALLENGE, ...). A failed sign-in is still a user.session.start event, just
with outcome FAILURE, and for an account that should never be used, failures
are the interesting part.

Matching is on actor.alternateId (the login) or actor.id.

One-shot mode reads a bounded window (--lookback-hours). --watch keeps polling
the System Log: each poll reads until Okta returns an empty page, then sleeps.

Examples:
    python scripts/break_glass_monitor.py --accounts "bg1@example.com,bg2@example.com"
    python scripts/break_glass_monitor.py --accounts bg1@example.com --lookback-hours 72 --json
    python scripts/break_glass_monitor.py --accounts bg1@example.com --watch --interval 120
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, utc_iso
from lib.okta_client import OktaClient
from lib.output import emit, table

EVENT_TYPES = (
    "user.session.start",
    "user.authentication.auth_via_mfa",
    "user.session.access_admin_app",
    "policy.evaluate_sign_on",
)
LOG_FILTER = " or ".join(f'eventType eq "{t}"' for t in EVENT_TYPES)


def match_event(event: dict, by_id: dict, by_login: dict) -> str | None:
    """Return the break-glass login this event belongs to, or None."""
    actor = event.get("actor") or {}
    if actor.get("id") in by_id:
        return by_id[actor["id"]]
    alt = (actor.get("alternateId") or "").lower()
    return by_login.get(alt)


def row_of(event: dict, account: str) -> dict:
    client = event.get("client") or {}
    geo = client.get("geographicalContext") or {}
    outcome = event.get("outcome") or {}
    return {
        "time": event.get("published"),
        "account": account,
        "event": event.get("eventType"),
        "result": outcome.get("result") or "UNKNOWN",
        "reason": outcome.get("reason") or "",
        "ip": client.get("ipAddress") or "",
        "location": ", ".join(p for p in (geo.get("city"), geo.get("country")) if p),
    }


def scan(events, by_id: dict, by_login: dict) -> list[dict]:
    return [row_of(e, acct) for e in events
            if (acct := match_event(e, by_id, by_login)) is not None]


def resolve_accounts(client: OktaClient, logins: list[str]) -> tuple[dict, dict]:
    by_id, by_login = {}, {}
    for login in logins:
        by_login[login.lower()] = login
        user = client.get_user_by_login(login)
        if user is None:
            print(f"warning: no Okta user found for {login}; matching on login only",
                  file=sys.stderr)
        else:
            by_id[user["id"]] = login
    return by_id, by_login


def watch(client: OktaClient, by_id: dict, by_login: dict, interval: int,
          polls: int | None = None, sleep=time.sleep) -> None:
    """Poll forever (or `polls` times, for tests) and print each match as JSON lines."""
    cursor = None
    since = utc_iso(datetime.now(UTC))
    n = 0
    while polls is None or n < polls:
        events, cursor = client.poll_logs(cursor, filter=LOG_FILTER, since=since)
        for r in scan(events, by_id, by_login):
            print(json.dumps(r), flush=True)
        n += 1
        if polls is None or n < polls:
            sleep(interval)


def main(argv=None):
    p = argparse.ArgumentParser(description="Report break-glass account sign-in "
                                "activity from the Okta System Log (read-only).")
    p.add_argument("--accounts", required=True, help="comma-separated logins")
    p.add_argument("--lookback-hours", type=int, default=24,
                   help="hours to scan in one-shot mode (default 24, max 2160)")
    p.add_argument("--watch", action="store_true", help="keep polling for new events")
    p.add_argument("--interval", type=int, default=300, help="seconds between polls (default 300)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    logins = [a.strip() for a in args.accounts.split(",") if a.strip()]
    if not logins:
        p.error("--accounts must list at least one login")

    client = connect()
    by_id, by_login = resolve_accounts(client, logins)

    if args.watch:
        print(f"watching {', '.join(logins)} every {args.interval}s (Ctrl-C to stop)",
              file=sys.stderr)
        try:
            watch(client, by_id, by_login, args.interval)
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)
        return

    since = utc_iso(datetime.now(UTC) - timedelta(hours=args.lookback_hours))
    rows = scan(client.list_logs(filter=LOG_FILTER, since=since), by_id, by_login)

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    summary = {"accounts": logins, "since": since, "events": len(rows), "by_result": counts}
    text = table([("TIME", 20), ("ACCOUNT", 30), ("EVENT", 32), ("RESULT", 9),
                  ("IP", 16), ("LOCATION", 0)],
                 [[(r["time"] or "")[:19].replace("T", " "), r["account"], r["event"],
                   r["result"], r["ip"], r["location"]] for r in rows])
    text += f"\n\n{len(rows)} events since {since}: " + (
        ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
    emit(report={"summary": summary, "events": rows}, text=text, as_json=args.json,
         output=args.output, csv_rows=rows)


if __name__ == "__main__":
    main()
