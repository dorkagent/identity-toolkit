#!/usr/bin/env python3
"""Rank Okta apps by SSO use and flag likely duplicates (read-only).

Usage is the count of user.authentication.sso events per app over
--lookback-days (at most 90). Flags:

    DUP         another app has the same label once case and punctuation are dropped
    NEAR-DUP    another app's label is at least --similarity alike (difflib ratio)
    SAME-TYPE   more than one instance of the same app integration (app "name")
    REMOVE?     no sign-ins in the window and nobody assigned

Apps that never emit SSO events (bookmarks, provisioning-only) will always
show zero sign-ins.

Examples:
    python scripts/app_rationalizer.py
    python scripts/app_rationalizer.py --lookback-days 30 --json --output apps.json
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, log_window
from lib.okta_client import OktaClient
from lib.output import emit, table


def normalize_label(label: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (label or "").lower())


def tally_logins(client: OktaClient, app_ids: set, since: str, until: str) -> dict:
    counts: dict[str, int] = {}
    for event in client.list_logs(filter='eventType eq "user.authentication.sso"',
                                  since=since, until=until):
        for target in event.get("target") or []:
            if target.get("id") in app_ids:
                counts[target["id"]] = counts.get(target["id"], 0) + 1
    return counts


def detect_duplicates(apps: list, similarity: float) -> dict[str, set]:
    flags: dict[str, set] = {a["id"]: set() for a in apps}
    norm: dict[str, list] = {}
    kinds: dict[str, list] = {}
    for a in apps:
        norm.setdefault(normalize_label(a.get("label")), []).append(a["id"])
        kinds.setdefault(a.get("name") or "?", []).append(a["id"])
    for ids in norm.values():
        if len(ids) > 1:
            for i in ids:
                flags[i].add("DUP")
    for ids in kinds.values():
        if len(ids) > 1:
            for i in ids:
                flags[i].add("SAME-TYPE")
    for i, a in enumerate(apps):
        for b in apps[i + 1:]:
            la, lb = a.get("label") or "", b.get("label") or ""
            if normalize_label(la) == normalize_label(lb):
                continue
            if difflib.SequenceMatcher(None, la.lower(), lb.lower()).ratio() >= similarity:
                flags[a["id"]].add("NEAR-DUP")
                flags[b["id"]].add("NEAR-DUP")
    return flags


def analyze(client: OktaClient, lookback_days: int, similarity: float, limit: int = 0):
    apps = list(client.list_apps())
    flags = detect_duplicates(apps, similarity)  # compare against every app
    if limit:
        apps = apps[:limit]
    since, until, _ = log_window(lookback_days)
    logins = tally_logins(client, {a["id"] for a in apps}, since, until)
    rows = []
    for app in apps:
        assigned = sum(1 for _ in client.list_app_users(app["id"]))
        f = set(flags[app["id"]])
        if logins.get(app["id"], 0) == 0 and assigned == 0:
            f.add("REMOVE?")
        rows.append({"app": app.get("label") or app["id"], "type": app.get("name") or "?",
                     "status": app.get("status"), "sign_ins": logins.get(app["id"], 0),
                     "assigned": assigned, "flags": sorted(f)})
    rows.sort(key=lambda r: r["sign_ins"], reverse=True)
    return rows, since


def main(argv=None):
    p = argparse.ArgumentParser(description="Rank Okta apps by SSO use and flag "
                                "duplicates (read-only).")
    p.add_argument("--lookback-days", type=int, default=90, help="days to read (max 90)")
    p.add_argument("--similarity", type=float, default=0.85,
                   help="label similarity for NEAR-DUP (default 0.85)")
    p.add_argument("--limit", type=int, default=0, help="only report the first N apps")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    rows, since = analyze(connect(), args.lookback_days, args.similarity, args.limit)
    summary = {"apps": len(rows), "since": since,
               "removal_candidates": sum(1 for r in rows if "REMOVE?" in r["flags"])}
    text = table([("APP", 40), ("TYPE", 24), ("SIGN-INS", 8), ("ASSIGNED", 8), ("FLAGS", 0)],
                 [[r["app"], r["type"], r["sign_ins"], r["assigned"], ",".join(r["flags"])]
                  for r in rows])
    text += f"\n\n{len(rows)} apps, {summary['removal_candidates']} removal candidates (since {since})"
    emit(report={"summary": summary, "apps": rows}, text=text, as_json=args.json,
         output=args.output, csv_rows=rows)


if __name__ == "__main__":
    main()
