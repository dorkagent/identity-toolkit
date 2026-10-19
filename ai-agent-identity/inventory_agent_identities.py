#!/usr/bin/env python3
"""AI agent identity risk review (report only).

Scans the shared Okta inventory contract (the same okta-inventory.json the
migration toolkit reads) for non-human identities an enterprise AI-agent
deployment would touch, and applies a deterministic risk rubric:

  * API tokens: never-expiring, orphaned (owner not in users), owned by an
    admin-role-linked user, older than 365 days.
  * OAuth/OIDC service apps: client_credentials grants, broad scopes.
  * Service-account users: admin group membership, human-like group
    memberships, dormant (non-ACTIVE) status.

Report only. No network calls, no tenant writes, no credential minting.
Everything runs offline against the inventory file.

Risk tiers: critical > high > medium > low. The highest matching rule wins;
every matched reason is listed so the finding is auditable.

Examples:
    python3 inventory_agent_identities.py
    python3 inventory_agent_identities.py --inventory /tmp/okta-inventory.json -o agent-risk.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "agent-inventory.sample.json")

TIER_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# A group whose name contains one of these is treated as an admin role.
ADMIN_GROUP_HINTS = ("admin",)
# Groups whose names contain one of these are treated as service-only, so
# membership in anything else on a service account looks human-like.
SERVICE_GROUP_HINTS = ("service", "svc", "bot", "agent", "automation",
                       "workload", "machine", "system")
# Scopes containing one of these are treated as broad for a machine client.
BROAD_SCOPE_HINTS = ("admin", ":manage", ":write", "*")

OLD_TOKEN_DAYS = 365


def parse_dt(value):
    if not value:
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def age_days(created, now):
    dt = parse_dt(created)
    if dt is None:
        return None
    return (now - dt).days


def bump(tier, candidate):
    if TIER_ORDER[candidate] < TIER_ORDER[tier]:
        return candidate
    return tier


def is_service_account(user):
    return user.get("userType") == "SERVICE" or \
        (user.get("login") or "").lower().startswith("svc_")


def is_service_group(name):
    lowered = (name or "").lower()
    return any(h in lowered for h in SERVICE_GROUP_HINTS)


def admin_group_ids(groups):
    return {g["id"] for g in groups
            if any(h in (g.get("name") or "").lower()
                   for h in ADMIN_GROUP_HINTS)}


def assess_token(tok, users_by_id, admin_ids, now):
    reasons = []
    tier = "low"
    uid = tok.get("userId")
    owner = users_by_id.get(uid) if uid else None

    if not tok.get("expiresAt"):
        reasons.append("never expires (no expiry set)")
        tier = bump(tier, "high")
    if uid and owner is None:
        reasons.append(f"orphaned: owner {uid} not in user inventory")
        tier = bump(tier, "high")
    if owner and any(g in admin_ids for g in owner.get("groups", [])):
        reasons.append("owner holds an admin role: token inherits admin power")
        tier = bump(tier, "critical")
    age = age_days(tok.get("created"), now)
    if age is not None and age > OLD_TOKEN_DAYS:
        reasons.append(f"token age {age} days (> {OLD_TOKEN_DAYS})")
        tier = bump(tier, "medium")
    return {"kind": "api_token", "tier": tier,
            "id": tok.get("id"), "name": tok.get("name") or "",
            "reasons": reasons}


def assess_oauth_app(app):
    reasons = []
    tier = "low"
    grants = app.get("grantTypes", []) or []
    scopes = app.get("scopes", []) or []

    if "client_credentials" in grants:
        reasons.append("client_credentials grant (machine-to-machine, "
                       "no user in the loop)")
        tier = bump(tier, "medium")
        broad = [s for s in scopes
                 if any(h in s.lower() for h in BROAD_SCOPE_HINTS)]
        if broad:
            reasons.append("broad scopes: " + ", ".join(broad))
            tier = bump(tier, "high")
        elif not scopes:
            reasons.append("no scopes exported: scope blast radius unknown, "
                           "re-export with scopes")
    elif grants:
        reasons.append("user-delegated flow only "
                       f"({', '.join(grants)}): no standalone machine credential")
    return {"kind": "oauth_service_app", "tier": tier,
            "id": app.get("id"),
            "name": app.get("label") or app.get("name") or "",
            "reasons": reasons}


def assess_service_user(user, groups_by_id, admin_ids):
    reasons = []
    tier = "low"
    gids = user.get("groups", []) or []

    if any(g in admin_ids for g in gids):
        reasons.append("service identity holds an admin role")
        tier = bump(tier, "high")
    else:
        human = sorted({groups_by_id[g]["name"] for g in gids
                        if g in groups_by_id
                        and not is_service_group(groups_by_id[g].get("name"))})
        if human:
            reasons.append("human-like group memberships: " + ", ".join(human))
            tier = bump(tier, "medium")
    status = (user.get("status") or "").upper()
    if status and status != "ACTIVE":
        reasons.append(f"account status is {status}: dormant identity "
                       "still present in the directory")
        tier = bump(tier, "medium")
    return {"kind": "service_user", "tier": tier,
            "id": user.get("id"), "name": user.get("login") or "",
            "reasons": reasons}


def collect(inv, now):
    users_by_id = {u["id"]: u for u in inv.get("users", [])}
    groups_by_id = {g["id"]: g for g in inv.get("groups", [])}
    admin_ids = admin_group_ids(inv.get("groups", []))

    findings = []
    for t in inv.get("apiTokens", []):
        findings.append(assess_token(t, users_by_id, admin_ids, now))
    for a in inv.get("oauthApps", []):
        findings.append(assess_oauth_app(a))
    for u in inv.get("users", []):
        if is_service_account(u):
            findings.append(assess_service_user(u, groups_by_id, admin_ids))
    findings.sort(key=lambda f: (TIER_ORDER[f["tier"]], f["kind"],
                                 f["name"] or ""))
    return findings


def coverage_check(inv):
    """Structural problems with the export itself (not risk findings)."""
    problems = []
    app_ids = {a["id"] for a in inv.get("apps", [])}
    for a in inv.get("oauthApps", []):
        if a.get("id") not in app_ids:
            problems.append(f"oauth app {a.get('label')} has no matching app "
                            "entry: re-run the export")
    for t in inv.get("apiTokens", []):
        if not t.get("userId"):
            problems.append(f"api token {t.get('name')} records no owner: "
                            "re-run the export")
    return problems


REMEDIATION = {
    "critical": "Rotate immediately and re-scope: replace with a short-lived, "
                "narrowly scoped credential owned by a dedicated service "
                "identity (never a human admin). Revoke the old token only "
                "after the consumer is verified on the new credential.",
    "high": "Schedule rotation this sprint: give the credential an expiry, "
            "narrow its scopes to the minimum the consumer needs, and confirm "
            "the owner still exists.",
    "medium": "Put on the hygiene backlog: set an expiry or rotation date, "
              "review group memberships, and confirm the identity is still "
              "needed.",
    "low": "No action: healthy posture, re-check on the normal review cycle.",
}


def render_markdown(findings, problems, source_label, now):
    lines = []
    lines.append("# AI agent identity risk review")
    lines.append("")
    lines.append(f"Source: `{source_label}` (offline inventory, no live calls)")
    lines.append(f"Reviewed: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    counts = {}
    for f in findings:
        counts[f["tier"]] = counts.get(f["tier"], 0) + 1
    for tier in ("critical", "high", "medium", "low"):
        lines.append(f"- **{tier}**: {counts.get(tier, 0)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Tier | Kind | ID | Name | Reasons |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        reasons = "<br>".join(f["reasons"]) if f["reasons"] else "none"
        lines.append(f"| {f['tier']} | {f['kind']} | {f['id']} | "
                     f"{f['name']} | {reasons} |")
    lines.append("")
    lines.append("## Coverage problems")
    lines.append("")
    if problems:
        for p in problems:
            lines.append(f"- !! {p}")
    else:
        lines.append("None: every inventoried credential resolved cleanly.")
    lines.append("")
    lines.append("## What to do first")
    lines.append("")
    for tier in ("critical", "high", "medium", "low"):
        lines.append(f"- **{tier}**: {REMEDIATION[tier]}")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Report-only risk review of non-human identities in an "
                    "Okta inventory: API tokens, OAuth service apps and "
                    "service-account users, scored for AI-agent-era risk.")
    p.add_argument("--inventory", default=FIXTURE_INV,
                   help="okta-inventory.json to scan (default: bundled fixture)")
    p.add_argument("-o", "--output",
                   help="write the Markdown report here (default: stdout)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        with open(args.inventory, encoding="utf-8") as fh:
            inv = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load inventory {args.inventory}: {exc}",
              file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    findings = collect(inv, now)
    problems = coverage_check(inv)
    report = render_markdown(findings, problems, args.inventory, now)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        print(report)

    if not args.quiet:
        counts = {}
        for f in findings:
            counts[f["tier"]] = counts.get(f["tier"], 0) + 1
        summary = ", ".join(f"{counts.get(t, 0)} {t}"
                            for t in ("critical", "high", "medium", "low"))
        print(f"{len(findings)} non-human identities reviewed: {summary}")
        if problems:
            print("coverage problems:")
            for pr in problems:
                print(f"  !! {pr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
