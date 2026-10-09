#!/usr/bin/env python3
"""List every Okta admin-role holder and flag grants that look unused.

Holders come from GET /api/v1/iam/assignees/users, which returns everyone with
a role whether it was assigned to them directly or through a group. For each
holder the script reads /api/v1/users/{id}/roles; each role comes back with
assignmentType USER (direct) or GROUP. All role types are reported, including
CUSTOM roles, REPORT_ADMIN and WORKFLOWS_ADMIN. Custom roles show their label.

A holder is flagged STALE when their oldest role assignment ("created") is
older than --stale-days and the System Log has no events with them as actor
inside the window. The System Log only keeps 90 days, so with --stale-days
above 90 the activity check still only covers the last 90 days.

MFA is summarised from the user's ACTIVE factors. On Identity Engine orgs the
factors API answers in the context of the admin's own client and enrollment
policy, so treat the MFA column as a hint, not an audit.

Examples:
    python scripts/admin_privilege_reviewer.py
    python scripts/admin_privilege_reviewer.py --stale-days 60 --json
    python scripts/admin_privilege_reviewer.py --output admins.csv
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect, log_window, parse_ts
from lib.okta_client import OktaClient, OktaError
from lib.output import emit, table

# Phishing-resistant factor types from the UserFactorType enum:
# webauthn and u2f are FIDO keys/passkeys, signed_nonce is Okta FastPass.
STRONG_FACTORS = {"webauthn", "u2f", "signed_nonce"}


def role_name(role: dict) -> str:
    if role.get("type") == "CUSTOM":
        return f"CUSTOM:{role.get('label') or role.get('role') or role.get('id')}"
    return role.get("type") or "?"


def mfa_summary(factors: list[dict]) -> str:
    active = [f for f in factors if f.get("status") == "ACTIVE"]
    if not active:
        return "none"
    strong = sorted({f["factorType"] for f in active if f.get("factorType") in STRONG_FACTORS})
    return f"{len(active)} active" + (f" ({', '.join(strong)})" if strong else ", none phishing-resistant")


def last_activity(client: OktaClient, user_id: str, since: str, until: str) -> str | None:
    last = None
    for event in client.list_logs(filter=f'actor.id eq "{user_id}"', since=since, until=until):
        published = event.get("published")
        if published and (last is None or published > last):
            last = published
    return last


def review(client: OktaClient, stale_days: int, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    since, until, _ = log_window(stale_days, now)
    rows = []
    for uid in client.list_role_assignee_user_ids():
        try:
            user = client.get(f"/api/v1/users/{uid}") or {}
            roles = list(client.list_user_roles(uid))
            factors = client.list_factors(uid)
        except OktaError as e:
            rows.append({"user_id": uid, "login": "?", "error": str(e)})
            continue
        profile = user.get("profile") or {}
        created = [d for d in (parse_ts(r.get("created")) for r in roles) if d]
        oldest = min(created) if created else None
        last = last_activity(client, uid, since, until)
        stale = bool(oldest and oldest < now - timedelta(days=stale_days) and not last)
        rows.append({
            "user_id": uid,
            "login": profile.get("login"),
            "status": user.get("status"),
            "direct_roles": sorted(role_name(r) for r in roles
                                   if r.get("assignmentType") == "USER"),
            "group_roles": sorted(role_name(r) for r in roles
                                  if r.get("assignmentType") == "GROUP"),
            "oldest_grant": oldest.date().isoformat() if oldest else None,
            "last_activity": last,
            "mfa": mfa_summary(factors),
            "stale": stale,
        })
    rows.sort(key=lambda r: (not r.get("stale"), r.get("login") or ""))
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description="Review Okta admin-role holders and flag "
                                "unused grants (read-only).")
    p.add_argument("--stale-days", type=int, default=90,
                   help="no activity in this many days marks a grant stale (default 90)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    client = connect()
    rows = review(client, args.stale_days)
    _, _, clipped = log_window(args.stale_days)

    summary = {"holders": len(rows), "stale": sum(1 for r in rows if r.get("stale")),
               "stale_days": args.stale_days,
               "activity_window_days": min(args.stale_days, 90)}
    text = table([("LOGIN", 34), ("DIRECT", 26), ("VIA GROUP", 26), ("GRANTED", 10),
                  ("LAST ACTIVITY", 19), ("MFA", 30), ("STALE", 0)],
                 [[r.get("login"), ",".join(r.get("direct_roles", [])),
                   ",".join(r.get("group_roles", [])), r.get("oldest_grant"),
                   (r.get("last_activity") or "none")[:19], r.get("mfa", r.get("error")),
                   "YES" if r.get("stale") else ""] for r in rows])
    text += f"\n\n{summary['holders']} role holders, {summary['stale']} stale"
    if clipped:
        text += " (activity checked over the last 90 days only; that is all Okta keeps)"
    emit(report={"summary": summary, "holders": rows}, text=text, as_json=args.json,
         output=args.output, csv_rows=rows,
         csv_fields=["login", "status", "direct_roles", "group_roles", "oldest_grant",
                     "last_activity", "mfa", "stale"])


if __name__ == "__main__":
    main()
