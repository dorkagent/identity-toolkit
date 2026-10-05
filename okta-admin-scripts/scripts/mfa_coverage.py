#!/usr/bin/env python3
"""MFA coverage auditor.

Reports, for every active user, whether they have:
  - no MFA enrolled at all,
  - only phishable factors (push, TOTP, SMS, voice, email, security question),
  - at least one phishing-resistant factor (WebAuthn/FIDO2, smart card).

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/mfa_coverage.py
    python scripts/mfa_coverage.py --json --output report.json
    python scripts/mfa_coverage.py --limit 25   # trial run on 25 users
"""

from __future__ import annotations

import argparse
import json
import sys

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError

# factorType -> strength. Anything unlisted is reported as "unknown"
# so new factor types surface instead of being silently misclassified.
PHISHABLE = {
    "push", "sms", "call", "question", "email",
    "token:software:totp", "token:hardware", "token",
}
STRONG = {"webauthn", "smart_card"}


def classify(factors: list) -> tuple[str, list[str]]:
    """Return (verdict, enrolled factor types)."""
    types = sorted({f.get("factorType", "?") for f in factors})
    if not types:
        return "none", types
    strengths = set()
    for t in types:
        if t in STRONG:
            strengths.add("strong")
        elif t in PHISHABLE:
            strengths.add("phishable")
        else:
            strengths.add("unknown")
    if strengths == {"strong"} or "strong" in strengths:
        return "strong", types
    if strengths == {"phishable"}:
        return "phishable-only", types
    return "unknown-mix", types


def audit(client: OktaClient, limit: int = 0, progress_every: int = 100):
    rows = []
    for n, user in enumerate(client.list_users(), 1):
        if limit and n > limit:
            break
        profile = user.get("profile", {})
        factors = client.list_factors(user["id"])
        verdict, types = classify(factors)
        rows.append({
            "login": profile.get("login"),
            "name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
            "verdict": verdict,
            "factors": types,
        })
        if n % progress_every == 0:
            print(f"... scanned {n} users", file=sys.stderr)
    return rows


def print_table(rows: list):
    verdicts = {"none": "NO MFA", "phishable-only": "PHISHABLE ONLY",
                "strong": "STRONG", "unknown-mix": "UNKNOWN MIX"}
    print(f"{'LOGIN':40} {'NAME':30} {'VERDICT':15} FACTORS")
    print("-" * 110)
    for r in rows:
        print(f"{(r['login'] or '')[:40]:40} {(r['name'] or '')[:30]:30} "
              f"{verdicts.get(r['verdict'], r['verdict']):15} {', '.join(r['factors'])}")


def main():
    p = argparse.ArgumentParser(description="Audit MFA enrollment across Okta users.")
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

    rows = audit(client, limit=args.limit)

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    summary = {"total_users": len(rows), **counts}

    if args.json:
        report = json.dumps({"summary": summary, "users": rows}, indent=2)
    else:
        print_table(rows)
        report_lines = [
            "",
            f"Scanned: {summary['total_users']} users | "
            f"no MFA: {counts.get('none', 0)} | "
            f"phishable-only: {counts.get('phishable-only', 0)} | "
            f"strong: {counts.get('strong', 0)}",
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
