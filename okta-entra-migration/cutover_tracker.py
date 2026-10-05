#!/usr/bin/env python3
"""LIFE-44: Track per-app cutover status with app owners.

Generates a tracker CSV from the inventory contract (or from the mapping
table produced by migrate_apps.py) -- one row per app:

    app_name, owner, status, last_updated, notes

Statuses: pending -> notified -> updated -> verified, plus rolled-back.

``--report`` prints outstanding items (everything not verified) grouped by
status. ``--set-status APP STATUS`` updates one row in an existing tracker
CSV (the operator's working file); updates are the operator's job -- the
script just keeps the file consistent.

Examples:
    python3 cutover_tracker.py                              # tracker to stdout
    python3 cutover_tracker.py -o tracker.csv
    python3 cutover_tracker.py --tracker tracker.csv --report
    python3 cutover_tracker.py --tracker tracker.csv \\
        --set-status Slack verified --note "pilot user OK"
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import load_inventory  # noqa: E402
from secure_io import csv_writer  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

HEADERS = ["app_name", "owner", "status", "last_updated", "notes"]
STATUSES = ("pending", "notified", "updated", "verified", "rolled-back")


def build_tracker(inv: dict) -> list[dict]:
    rows = []
    for a in inv.get("apps", []):
        rows.append({
            "app_name": a.get("label") or a.get("name"),
            "owner": a.get("owner") or "",
            "status": "pending",
            "last_updated": date.today().isoformat(),
            "notes": "",
        })
    return rows


def read_tracker(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_tracker(rows: list[dict], fh) -> None:
    w = csv.DictWriter(fh, fieldnames=HEADERS)
    w.writeheader()
    w.writerows(rows)


def write_tracker_csv(rows: list[dict], path: str | None) -> None:
    """Write the tracker CSV: atomic + 0600 for files, stdout for -/None."""
    with csv_writer(path, HEADERS) as w:
        w.writeheader()
        w.writerows(rows)


def outstanding_report(rows: list[dict]) -> str:
    open_rows = [r for r in rows if r["status"] != "verified"]
    lines = [f"outstanding: {len(open_rows)} of {len(rows)} apps"]
    by_status: dict[str, list] = {}
    for r in open_rows:
        by_status.setdefault(r["status"], []).append(r)
    for status in STATUSES:
        for r in by_status.get(status, []):
            owner = f" (owner: {r['owner']})" if r["owner"] else " (owner: UNASSIGNED)"
            lines.append(f"  [{status}] {r['app_name']}{owner}")
    if not any(not r["owner"] for r in open_rows):
        pass
    unowned = [r["app_name"] for r in open_rows if not r["owner"]]
    if unowned:
        lines.append("apps with no owner assigned: " + ", ".join(unowned))
    return "\n".join(lines)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Generate and maintain the per-app cutover tracker CSV.")
    p.add_argument("--inventory", default=FIXTURE_INV,
                   help="inventory contract (used when --tracker is absent)")
    p.add_argument("--tracker", help="existing tracker CSV to work with")
    p.add_argument("-o", "--output",
                   help="write tracker CSV here (default: stdout)")
    p.add_argument("--report", action="store_true",
                   help="print outstanding-items report")
    p.add_argument("--set-status", nargs=2, metavar=("APP", "STATUS"),
                   help="update one row's status in --tracker (writes back)")
    p.add_argument("--note", default="", help="note to attach with --set-status")
    p.add_argument("--owner", default=None,
                   help="set owner with --set-status")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print

    if args.set_status:
        if not args.tracker:
            print("error: --set-status requires --tracker", file=sys.stderr)
            return 2
        app, status = args.set_status
        if status not in STATUSES:
            print(f"error: status must be one of {STATUSES}", file=sys.stderr)
            return 2
        rows = read_tracker(args.tracker)
        hit = [r for r in rows if r["app_name"].lower() == app.lower()]
        if not hit:
            print(f"error: no app named {app!r} in tracker", file=sys.stderr)
            return 2
        for r in hit:
            r["status"] = status
            r["last_updated"] = date.today().isoformat()
            if args.note:
                r["notes"] = (r["notes"] + " | " + args.note).strip(" |")
            if args.owner is not None:
                r["owner"] = args.owner
        with csv_writer(args.tracker, HEADERS) as w:
            w.writeheader()
            w.writerows(rows)
        log(f"{app}: status -> {status}")
        return 0

    rows = read_tracker(args.tracker) if args.tracker \
        else build_tracker(load_inventory(args.inventory))

    if args.report:
        print(outstanding_report(rows))
        return 0

    if args.output:
        write_tracker_csv(rows, args.output)
        log(f"tracker: {len(rows)} apps -> {args.output}")
    else:
        write_tracker(rows, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
