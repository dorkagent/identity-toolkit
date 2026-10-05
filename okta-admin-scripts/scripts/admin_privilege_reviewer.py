#!/usr/bin/env python3
"""Admin privilege reviewer (READ-ONLY).

Collects every holder of an elevated Okta admin role, both directly assigned
to users and granted via groups, and flags stale grants: a role assigned
longer than --stale-days ago with no System Log activity from that user
since then.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/admin_privilege_reviewer.py
    python scripts/python/admin_privilege_reviewer.py --stale-days 90 --limit 25
    python scripts/python/admin_privilege_reviewer.py --json --output admin_review.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError

# Every role type treated as "elevated" for this review.
ELEVATED_ROLES = {
    "SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "GROUP_ADMIN",
    "GROUP_MEMBERSHIP_ADMIN", "HELP_DESK_ADMIN", "MOBILE_ADMIN",
    "API_ACCESS_MANAGEMENT_ADMIN", "USER_ADMIN",
}

STRONG_FACTORS = {"webauthn", "smart_card"}


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_date(value: str | None):
    """Return a date for an Okta timestamp, or None if unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def grant_date_of(role: dict) -> str | None:
    """assignmentDate preferred, created as fallback (per role API shape)."""
    return role.get("assignmentDate") or role.get("created")


def user_activity(client: OktaClient, user_id: str, cutoff_iso: str):
    """Return (last_activity_iso, active_since_cutoff) from the System Log.

    One pass over events where this user is the actor; keeps the newest
    published timestamp and whether anything happened since the cutoff.
    """
    last, recent = None, False
    for event in client.list_logs(filter=f'actor.id eq "{user_id}"'):
        published = event.get("published") or ""
        if published and (last is None or published > last):
            last = published
        if published and published > cutoff_iso:
            recent = True
    return last, recent


def mfa_summary(client: OktaClient, user_id: str) -> str:
    factors = client.list_factors(user_id)
    if not factors:
        return "none"
    strong = any(f.get("factorType") in STRONG_FACTORS for f in factors)
    return f"{len(factors)}{' (strong)' if strong else ''}"


def review_users(client: OktaClient, stale_days: int, limit: int = 0,
                 progress_every: int = 100):
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=stale_days)
    cutoff_iso = utc_iso(datetime.now(timezone.utc) - timedelta(days=stale_days))
    rows = []
    for n, user in enumerate(client.list_users(status="ACTIVE"), 1):
        if limit and n > limit:
            break
        roles = [r for r in client.list_user_roles(user["id"])
                 if r.get("type") in ELEVATED_ROLES]
        if not roles:
            if n % progress_every == 0:
                print(f"... scanned {n} users", file=sys.stderr)
            continue
        profile = user.get("profile", {})
        grants = [(r.get("type"), grant_date_of(r)) for r in roles]
        grant_dates = [parse_date(g) for _, g in grants]
        known = [d for d in grant_dates if d]
        earliest = min(known).isoformat() if known else "unknown"

        last_action, recent = user_activity(client, user["id"], cutoff_iso)
        stale = any(d and d < cutoff for d in grant_dates) and not recent

        rows.append({
            "login": profile.get("login"),
            "name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            "roles": sorted({t for t, _ in grants}),
            "grant_date": earliest,
            "last_admin_action": last_action or "none",
            "mfa": mfa_summary(client, user["id"]),
            "stale": stale,
        })
        if n % progress_every == 0:
            print(f"... scanned {n} users", file=sys.stderr)
    return rows


def review_groups(client: OktaClient):
    """Groups that carry role grants: name, role types, member count."""
    rows = []
    for group in client.list_groups():
        groles = [r.get("type") for r in client.list_group_roles(group["id"])]
        if not groles:
            continue
        members = sum(1 for _ in
                      client.paged_get(f"/api/v1/groups/{group['id']}/users"))
        rows.append({
            "group": (group.get("profile") or {}).get("name", group["id"]),
            "roles": sorted(set(groles)),
            "members": members,
        })
    return rows


def print_table(rows: list):
    print(f"{'LOGIN':38} {'NAME':24} {'ROLES':34} {'GRANT':11} "
          f"{'LAST ADMIN ACTION':20} {'MFA':12} STALE?")
    print("-" * 160)
    for r in rows:
        last = (r["last_admin_action"] or "")[:19].replace("T", " ")
        print(f"{(r['login'] or '')[:38]:38} {(r['name'] or '')[:24]:24} "
              f"{','.join(r['roles'])[:34]:34} {r['grant_date']:11} "
              f"{last:20} {(r['mfa'] or '')[:12]:12} "
              f"{'YES' if r['stale'] else '-'}")


def print_group_table(rows: list):
    if not rows:
        return
    print("\nGroups holding role grants:")
    print(f"{'GROUP':45} {'ROLES':50} MEMBERS")
    print("-" * 105)
    for r in rows:
        print(f"{(r['group'] or '')[:45]:45} {','.join(r['roles'])[:50]:50} "
              f"{r['members']}")


def main():
    p = argparse.ArgumentParser(
        description="Review Okta admin-role holders and flag stale grants (read-only).")
    p.add_argument("--stale-days", type=int, default=180,
                   help="grant older than this with no log activity is STALE (default 180)")
    p.add_argument("--limit", type=int, default=0,
                   help="only scan N users (0 = all)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    print("scanning user role assignments...", file=sys.stderr)
    users = review_users(client, args.stale_days, limit=args.limit)
    print("scanning group role grants...", file=sys.stderr)
    groups = review_groups(client)

    n_stale = sum(1 for r in users if r["stale"])

    if args.json:
        report = json.dumps({
            "stale_days": args.stale_days,
            "summary": {"privileged_users": len(users),
                        "stale_grants": n_stale,
                        "groups_with_roles": len(groups)},
            "users": users,
            "group_roles": groups,
        }, indent=2)
    else:
        print_table(users)
        print_group_table(groups)
        report = (f"\nPrivileged users: {len(users)} | stale grants: {n_stale} | "
                  f"groups holding roles: {len(groups)}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report if args.json else report + "\n")
        print(f"\nwrote {args.output}", file=sys.stderr)
    elif not args.json:
        print(report)


if __name__ == "__main__":
    main()
