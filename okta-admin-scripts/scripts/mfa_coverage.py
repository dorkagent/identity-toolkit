#!/usr/bin/env python3
"""MFA enrollment per user, from the factors API.

For each ACTIVE user, looks at factors with status ACTIVE and sorts the user
into one of:
    none              no active factor
    phishable-only    only push, OTP, SMS, voice, email, security question
    mixed             at least one phishing-resistant factor, but phishable
                      ones are still enrolled and usable as a fallback
    strong-only       only phishing-resistant factors (webauthn, u2f, FastPass)
    unknown           a factor type this script doesn't recognise

Caveat for Identity Engine orgs: GET /api/v1/users/{id}/factors only returns
factors from the highest-priority authenticator enrollment policy and uses the
calling admin's client context, so results can be incomplete. Okta's own MFA
Usage report is the better source for a formal audit.

Examples:
    python scripts/mfa_coverage.py --limit 25
    python scripts/mfa_coverage.py --json --output mfa.json
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect
from lib.okta_client import OktaError
from lib.output import emit, table

# From the UserFactorType enum in the Okta management API spec.
STRONG = {"webauthn", "u2f", "signed_nonce"}
PHISHABLE = {"push", "sms", "call", "question", "email", "token:software:totp",
             "token:hardware", "token:hotp", "token", "web"}


def classify(factors: list[dict]) -> tuple[str, list[str]]:
    types = sorted({f.get("factorType", "?") for f in factors if f.get("status") == "ACTIVE"})
    if not types:
        return "none", types
    strong = [t for t in types if t in STRONG]
    weak = [t for t in types if t in PHISHABLE]
    if len(strong) + len(weak) < len(types):
        return "unknown", types
    if strong and weak:
        return "mixed", types
    return ("strong-only" if strong else "phishable-only"), types


def audit(client, limit: int = 0) -> list[dict]:
    rows = []
    for n, user in enumerate(client.list_users(status="ACTIVE"), 1):
        if limit and n > limit:
            break
        profile = user.get("profile") or {}
        try:
            verdict, types = classify(client.list_factors(user["id"]))
        except OktaError as e:
            verdict, types = "error", [str(e)]
        rows.append({"login": profile.get("login"), "verdict": verdict, "factors": types})
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description="Report MFA enrollment for active Okta users.")
    p.add_argument("--limit", type=int, default=0, help="only check the first N users")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    rows = audit(connect(), args.limit)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    text = table([("LOGIN", 40), ("VERDICT", 15), ("ACTIVE FACTORS", 0)],
                 [[r["login"], r["verdict"], ", ".join(r["factors"])] for r in rows])
    text += f"\n\n{len(rows)} users: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    emit(report={"summary": {"users": len(rows), **counts}, "users": rows}, text=text,
         as_json=args.json, output=args.output, csv_rows=rows)


if __name__ == "__main__":
    main()
