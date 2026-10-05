#!/usr/bin/env python3
"""Application rationalization report (DHQ-87).

Ranks every Okta app by real usage (System Log logins over a lookback
window), flags duplicates / near-duplicates / same-vendor sprawl, and
identifies removal candidates (zero logins AND zero assigned users).

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/app_rationalizer.py
    python scripts/python/app_rationalizer.py --lookback-days 30 --limit 50
    python scripts/python/app_rationalizer.py --json --output apps.json
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError


def normalize_label(label: str) -> str:
    """Lowercase and strip everything that is not alphanumeric."""
    return re.sub(r"[^a-z0-9]", "", (label or "").lower())


def tally_logins(client: OktaClient, app_ids: set, cutoff: str) -> dict:
    """Single pass over the System Log; count logins per app id.

    Matches event.target ids against known app ids. `user.session.start`
    events generally target the user, while `user.authentication.sso`
    events target the app -- both are included per the acceptance spec.
    """
    counts: dict[str, int] = {}
    n = 0
    log_filter = ('eventType eq "user.authentication.sso" '
                  'or eventType eq "user.session.start"')
    for event in client.list_logs(filter=log_filter, since=cutoff):
        n += 1
        for target in event.get("target") or []:
            tid = target.get("id")
            if tid in app_ids:
                counts[tid] = counts.get(tid, 0) + 1
        if n % 50000 == 0:
            print(f"... scanned {n} log events", file=sys.stderr)
    print(f"... scanned {n} log events", file=sys.stderr)
    return counts


def detect_duplicates(apps: list, similarity: float) -> dict:
    """Return {app_id: set(flags)} with DUP / NEAR-DUP / VENDOR-DUP flags."""
    flags: dict[str, set] = {a["id"]: set() for a in apps}

    # Exact duplicates: same normalized label.
    norm_counts: dict[str, int] = {}
    for a in apps:
        norm = normalize_label(a.get("label"))
        norm_counts[norm] = norm_counts.get(norm, 0) + 1
    for a in apps:
        if norm_counts[normalize_label(a.get("label"))] > 1:
            flags[a["id"]].add("DUP")

    # Near-duplicates: pairwise label similarity above threshold.
    labels = [(a["id"], a.get("label") or "") for a in apps]
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            ai, li = labels[i]
            aj, lj = labels[j]
            if normalize_label(li) == normalize_label(lj):
                continue  # already flagged as DUP
            if difflib.SequenceMatcher(None, li, lj).ratio() >= similarity:
                flags[ai].add("NEAR-DUP")
                flags[aj].add("NEAR-DUP")

    # Vendor sprawl: same vendor (app["name"]) with multiple instances.
    vendor_counts: dict[str, int] = {}
    for a in apps:
        vendor_counts[a.get("name") or "?"] = \
            vendor_counts.get(a.get("name") or "?", 0) + 1
    for a in apps:
        if vendor_counts[a.get("name") or "?"] > 1:
            flags[a["id"]].add("VENDOR-DUP")

    return flags


def analyze(client: OktaClient, lookback_days: int, similarity: float,
            limit: int = 0):
    apps = list(client.list_apps())
    if limit:
        apps = apps[:limit]
    app_ids = {a["id"] for a in apps}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)) \
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")
    logins = tally_logins(client, app_ids, cutoff)

    flags = detect_duplicates(apps, similarity)

    rows = []
    for n, app in enumerate(apps, 1):
        assigned = sum(1 for _ in client.list_app_users(app["id"]))
        if n % 25 == 0:
            print(f"... counted assignments for {n}/{len(apps)} apps",
                  file=sys.stderr)
        app_flags = set(flags[app["id"]])
        login_count = logins.get(app["id"], 0)
        if login_count == 0 and assigned == 0:
            app_flags.add("REMOVE?")
        rows.append({
            "app": app.get("label") or app["id"],
            "vendor": app.get("name") or "?",
            "logins": login_count,
            "assigned": assigned,
            "flags": sorted(app_flags),
        })
    rows.sort(key=lambda r: r["logins"], reverse=True)
    return rows


def print_table(rows: list, lookback_days: int):
    print(f"{'APP':40} {'VENDOR':22} {'LOGINS(' + str(lookback_days) + 'd)':>12} "
          f"{'ASSIGNED':>8}  FLAGS")
    print("-" * 100)
    for r in rows:
        print(f"{r['app'][:40]:40} {r['vendor'][:22]:22} "
              f"{r['logins']:>12} {r['assigned']:>8}  "
              f"{','.join(r['flags'])}")


def main():
    p = argparse.ArgumentParser(
        description="Rank Okta apps by usage and flag duplicates / "
                    "removal candidates.")
    p.add_argument("--lookback-days", type=int, default=90,
                   help="login lookback window in days (default 90)")
    p.add_argument("--similarity", type=float, default=0.85,
                   help="label similarity threshold for near-duplicate "
                        "detection (default 0.85)")
    p.add_argument("--limit", type=int, default=0,
                   help="only analyze N apps (0 = all)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    rows = analyze(client, args.lookback_days, args.similarity,
                   limit=args.limit)

    summary = {
        "total_apps": len(rows),
        "total_logins": sum(r["logins"] for r in rows),
        "duplicates": sum(1 for r in rows if "DUP" in r["flags"]),
        "near_duplicates": sum(1 for r in rows if "NEAR-DUP" in r["flags"]),
        "vendor_dup_instances": sum(1 for r in rows
                                    if "VENDOR-DUP" in r["flags"]),
        "removal_candidates": sum(1 for r in rows if "REMOVE?" in r["flags"]),
    }

    if args.json:
        report = json.dumps({"summary": summary, "apps": rows}, indent=2)
    else:
        print_table(rows, args.lookback_days)
        report = ("\n"
                  f"Apps: {summary['total_apps']} | "
                  f"logins({args.lookback_days}d): {summary['total_logins']} | "
                  f"dup: {summary['duplicates']} | "
                  f"near-dup: {summary['near_duplicates']} | "
                  f"vendor-dup: {summary['vendor_dup_instances']} | "
                  f"removal candidates: {summary['removal_candidates']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
