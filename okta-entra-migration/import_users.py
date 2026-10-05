#!/usr/bin/env python3
"""LIFE-41: Import users into Entra ID with match-and-merge.

Default (offline) mode matches inventory users against a local Entra tenant
fixture on userPrincipalName and prints a dry-run report:
matched / would-create / flagged-for-review. Duplicates and conflicts are
NEVER imported blindly -- they go to a human review list.

Live mode (``--live``) reads the Entra tenant via Microsoft Graph using
client-credentials from env (GRAPH_TENANT_ID, GRAPH_CLIENT_ID,
GRAPH_CLIENT_SECRET). ``--apply`` actually creates missing users in Entra;
without it, live mode is still a dry run.

Safety guards (all modes):

* AD/LDAP-mastered Okta users are never created as cloud duplicates --
  they arrive in Entra via Entra Connect sync instead.
* Domain preflight (live mode): a user whose UPN domain is not a verified
  domain in the Entra tenant is flagged, not created.
* Matching is tiered: exact UPN first, then email; an email match with a
  different UPN is flagged as a possible rename, never auto-merged.
* Create-only mutation policy: matched Entra users are never modified,
  flagged users are never imported, nothing is ever deleted.

``--apply`` onboards each created user with a Temporary Access Pass
(single-use, time-limited -- the Microsoft-recommended migration credential).
The TAP is printed once to stdout and never written into the JSON report;
use ``--tap-file`` to also save TAPs to an explicitly requested 0600 file.
Creating TAPs requires the app registration to hold
``UserAuthenticationMethod.ReadWrite.All``.

``--apply`` prints the connected tenant and asks for confirmation (type
APPLY) unless ``--yes`` is given. Every mutation is appended to an audit
log (default ``toolkit.audit.jsonl``): who, what, when, which tenant --
never secret values.

Examples:
    python3 import_users.py                                  # dry run vs fixture
    python3 import_users.py --live                            # dry run vs Graph
    python3 import_users.py --live --apply                    # create missing users
    python3 import_users.py --live --apply --yes               # no confirmation
    python3 import_users.py --live --apply --tap-file taps.txt
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import load_inventory  # noqa: E402
from graph_api import GraphClient  # noqa: E402
from secure_io import write_json, atomic_write_text  # noqa: E402
from journal import Journal  # noqa: E402
from audit import AuditLog  # noqa: E402
from tenant_guard import check_graph_tenant, confirm_apply  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")
FIXTURE_ENTRA = os.path.join(os.path.dirname(__file__), "fixtures",
                             "entra-tenant.sample.json")

# Okta credential-provider types whose identities are mastered outside Okta.
# Creating Entra cloud users for these would produce duplicates that fight
# the real provisioning path (Entra Connect sync) -- always flag instead.
AD_MASTERED_PROVIDERS = ("ACTIVE_DIRECTORY", "LDAP")

# Declared mutation policy, stamped into every report: this tool is
# create-only. If the policy ever widens, this constant is the changelog.
MUTATION_POLICY = {
    "mode": "create-only",
    "setsOnCreate": [
        "accountEnabled", "displayName", "mailNickname",
        "userPrincipalName", "mail", "givenName", "surname",
        "jobTitle", "department", "usageLocation",
        "passwordProfile (random value, never stored or reported)",
    ],
    "neverUpdates": "users matched to an existing Entra account are "
                    "never modified",
    "neverImports": "flagged users (deprovisioned, AD-mastered, service "
                    "accounts, conflicts, unverified domains) are never "
                    "imported",
    "neverDeletes": True,
}


def is_service_account(user: dict) -> bool:
    return user.get("userType") == "SERVICE" or \
        (user.get("login") or "").lower().startswith("svc_")


def match_users(okta_users: list[dict], entra_users: list[dict]) -> dict:
    """Return {'matched', 'to_create', 'flagged'} buckets.

    Tier 1: exact UPN match. Tier 2: email match (possible UPN rename --
    flagged, never auto-merged). No match: would-create, unless a guard
    fires (deprovisioned, AD-mastered, service account).
    """
    by_upn = {u.get("userPrincipalName", "").lower(): u
              for u in entra_users if u.get("userPrincipalName")}
    by_email = {u.get("mail", "").lower(): u
                for u in entra_users if u.get("mail")}
    matched, to_create, flagged = [], [], []

    for ou in okta_users:
        login = (ou.get("login") or "").strip()
        if not login:
            flagged.append({"user": ou, "reason": "no login/UPN in inventory"})
            continue
        if ou.get("status") == "DEPROVISIONED":
            flagged.append({"user": ou,
                            "reason": "deprovisioned in Okta -- no import; "
                                      "review Entra account lifecycle"})
            continue
        provider = (ou.get("credentialProvider") or "").upper()
        if provider in AD_MASTERED_PROVIDERS:
            flagged.append({"user": ou,
                            "reason": f"identity mastered in on-prem "
                                      f"{provider} -- do not create a cloud "
                                      f"duplicate; provision via Entra "
                                      f"Connect sync instead"})
            continue
        eu = by_upn.get(login.lower())
        if eu is None:
            em = by_email.get((ou.get("email") or "").lower())
            if em is not None:
                flagged.append({"user": ou, "entraUser": em,
                                "reason": f"UPN {login!r} not found in Entra "
                                          f"but email matches "
                                          f"{em.get('userPrincipalName')!r} "
                                          f"-- possible UPN rename; review "
                                          f"before merging"})
                continue
            if is_service_account(ou):
                flagged.append({"user": ou,
                                "reason": "service account -- handled by "
                                          "inventory_service_accounts.py, "
                                          "not by user import"})
            else:
                to_create.append({"user": ou})
            continue
        conflicts = []
        for okta_field, entra_field in (("email", "mail"),
                                       ("firstName", "givenName"),
                                       ("lastName", "surname")):
            ov, ev = ou.get(okta_field), eu.get(entra_field)
            if ov and ev and ov.strip().lower() != ev.strip().lower():
                conflicts.append(f"{okta_field}: okta={ov!r} entra={ev!r}")
        if not eu.get("accountEnabled", True):
            conflicts.append("Entra account is disabled")
        if conflicts:
            flagged.append({"user": ou, "entraUser": eu,
                            "reason": "UPN matches but attributes differ: "
                                      + "; ".join(conflicts)})
        else:
            matched.append({"user": ou, "entraUser": eu})
    return {"matched": matched, "to_create": to_create, "flagged": flagged}


def entra_user_payload(okta_user: dict, domain: str) -> dict:
    """Graph user body for a net-new user (mailNickname derived from login)."""
    login = okta_user["login"]
    nick = login.split("@")[0]
    return {
        "accountEnabled": okta_user.get("status") == "ACTIVE",
        "displayName": f"{okta_user.get('firstName', '')} "
                       f"{okta_user.get('lastName', '')}".strip() or login,
        "mailNickname": nick,
        "userPrincipalName": login,
        "mail": okta_user.get("email") or login,
        "givenName": okta_user.get("firstName"),
        "surname": okta_user.get("lastName"),
        "jobTitle": okta_user.get("title"),
        "department": okta_user.get("department"),
        # NOTE: Graph requires 'passwordProfile' on create. The apply loop
        # fills it with a random value that is never stored or reported --
        # the Temporary Access Pass created right after is the onboarding
        # credential.
        "usageLocation": "US",
    }


def report_text(buckets: dict) -> str:
    lines = []
    lines.append(f"matched:     {len(buckets['matched'])}")
    lines.append(f"would-create: {len(buckets['to_create'])}")
    lines.append(f"flagged:     {len(buckets['flagged'])}")
    if buckets["flagged"]:
        lines.append("\nflagged for human review:")
        for f in buckets["flagged"]:
            u = f["user"]
            lines.append(f"  - {u.get('login')} ({u.get('id')}): {f['reason']}")
    lines.append("\nmutation policy: create-only -- matched users are never "
                 "modified, flagged users are never imported, nothing is "
                 "deleted")
    return "\n".join(lines)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Match Okta users against Entra and plan the import "
                    "(dry run by default; conflicts never auto-import).")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("--entra-fixture", default=FIXTURE_ENTRA,
                   help="local Entra tenant JSON (offline mode)")
    p.add_argument("--live", action="store_true",
                   help="read Entra via Microsoft Graph "
                        "(GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET)")
    p.add_argument("--apply", action="store_true",
                   help="create missing users in Entra (requires --live; "
                        "still never imports flagged users; asks for "
                        "confirmation unless --yes)")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive APPLY confirmation "
                        "(for automation; you own the consequences)")
    p.add_argument("--audit-log", default="toolkit.audit.jsonl",
                   help="append-only audit trail of every mutation "
                        "(default: %(default)s)")
    p.add_argument("--tap-file",
                   help="also save issued Temporary Access Passes to this "
                        "file (0600). The JSON report never carries TAPs.")
    p.add_argument("--no-tap", action="store_true",
                   help="skip Temporary Access Pass creation (use the org's "
                        "own onboarding credential instead)")
    p.add_argument("--journal", default="import-users.journal.jsonl",
                   help="checkpoint journal for --apply: a rerun skips items "
                        "already ok/skipped and retries errors "
                        "(default: %(default)s)")
    p.add_argument("--report", help="write JSON report to this path")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    inv = load_inventory(args.inventory)
    okta_users = inv["users"]

    if args.live:
        gc = GraphClient()
        org = check_graph_tenant(gc, log)
        if org is None:
            return 2
        entra_users = list(gc.list_users())
    else:
        org = {}
        with open(args.entra_fixture, encoding="utf-8") as fh:
            entra_users = json.load(fh)["users"]

    buckets = match_users(okta_users, entra_users)

    if args.live:
        # Domain preflight: Graph rejects user creation under an unverified
        # domain, so flag those users instead of attempting them.
        verified = {d.get("id", "").lower() for d in gc.list_domains()
                    if d.get("isVerified")}
        kept = []
        for item in buckets["to_create"]:
            domain = item["user"]["login"].split("@")[-1].lower()
            if domain not in verified:
                buckets["flagged"].append({
                    "user": item["user"],
                    "reason": f"UPN domain {domain!r} is not a verified "
                              f"domain in the Entra tenant -- verify the "
                              f"domain (or fix the UPN) before creating"})
                log(f"domain-preflight: skipping {item['user']['login']} "
                    f"(unverified domain {domain!r})")
            else:
                kept.append(item)
        buckets["to_create"] = kept

    if args.apply:
        if not args.live:
            print("error: --apply requires --live", file=sys.stderr)
            return 2
        import secrets
        journal = Journal(args.journal)
        summary = (
            f"About to create up to {len(buckets['to_create'])} user(s) in "
            f"Entra tenant {org.get('displayName') or '?'} "
            f"({org.get('id') or '?'}).\n"
            f"Journal: {args.journal}  |  Audit log: {args.audit_log}\n"
            f"Flagged users are never imported; matched users are never "
            f"modified.")
        if not confirm_apply(summary, args.yes):
            print("aborted -- nothing was created", file=sys.stderr)
            return 1
        audit = AuditLog(args.audit_log, script="import_users",
                         tenant=org.get("id", ""))
        audit.record("apply-start", detail={
            "candidates": len(buckets["to_create"]),
            "journal": args.journal})
        tap_lines = []
        n_created = n_failed = n_resumed = 0
        for item in buckets["to_create"]:
            login = item["user"]["login"]
            if journal.completed(login):
                item["resumed"] = True
                n_resumed += 1
                log(f"resume-skip (already done): {login}")
                continue
            try:
                body = entra_user_payload(item["user"], "")
                # Random password satisfies Graph's required passwordProfile;
                # it is never stored or reported -- the TAP below onboards.
                body["passwordProfile"] = {
                    "forceChangePasswordNextSignIn": True,
                    "password": secrets.token_urlsafe(32)}
                created = gc.create_user(body)
                item["createdEntraId"] = created.get("id")
                audit.record("create-user", "user", created.get("id"), login,
                             {"oktaId": item["user"].get("id")})
                log(f"created {login} -> {created.get('id')}")
                if not args.no_tap:
                    try:
                        tap = gc.create_temporary_access_pass(created["id"])
                        value = tap.get("temporaryAccessPass")
                        item["tapCreated"] = True
                        item["tapId"] = tap.get("id")
                        # Audit notes the TAP was issued -- never its value.
                        audit.record("issue-tap", "temporaryAccessPass",
                                     tap.get("id"), login,
                                     {"oktaId": item["user"].get("id")})
                        if args.tap_file:
                            tap_lines.append(f"{login}\t{value}")
                        # Shown once on stdout; never written into the report.
                        print(f"TAP for {login}: {value}")
                    except Exception as e:  # TAP best-effort; user exists
                        item["tapCreated"] = False
                        item["tapError"] = str(e)[:200]
                        log(f"WARNING: TAP failed for {login}: {e} -- "
                            f"create one manually in Entra admin center")
                else:
                    item["tapCreated"] = False
                journal.record(login, "ok",
                               {"entraId": created.get("id"),
                                "tapCreated": item.get("tapCreated")})
                n_created += 1
            except Exception as e:
                # One bad user must not abort the batch; the journal lets a
                # rerun retry exactly the failures.
                journal.record(login, "error", str(e)[:300])
                item["applyError"] = str(e)[:300]
                audit.record("create-user-failed", "user", "", login,
                             {"oktaId": item["user"].get("id"),
                              "error": str(e)[:200]})
                n_failed += 1
                log(f"ERROR creating {login}: {e} -- continuing")
        if tap_lines:
            atomic_write_text(args.tap_file,
                              "".join(l + "\n" for l in tap_lines),
                              mode=0o600)
            log(f"TAPs saved to {args.tap_file} (0600 -- handle as secrets)")
        log(f"apply done: {n_created} created, {n_failed} failed, "
            f"{n_resumed} resumed-skipped (journal: {args.journal})")
        audit.record("apply-done", detail={
            "created": n_created, "failed": n_failed,
            "resumed": n_resumed})

    text = report_text(buckets)
    log(text)
    if args.report:
        # Scrubbed + 0600 + atomic: reports never carry secrets, even if a
        # future code path accidentally attaches one to a bucket item.
        write_json(args.report,
                   {**buckets, "mutationPolicy": MUTATION_POLICY})
        log(f"report written to {args.report}")
    if args.apply and not args.no_tap and \
            any(i.get("tapCreated") for i in buckets["to_create"]):
        log("NOTE: Temporary Access Passes printed above are single-use and "
            "time-limited; distribute them via your normal onboarding "
            "channel. They are not stored in the report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
