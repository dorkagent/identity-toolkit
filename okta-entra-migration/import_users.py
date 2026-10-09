#!/usr/bin/env python3
"""Match Okta users against Entra ID and create the ones that are missing.

Offline (default) matches inventory users against a local Entra fixture and
prints a dry-run report: matched / would-create / flagged for review.
``--live`` reads the tenant through Microsoft Graph; ``--apply`` creates
missing users. Without ``--apply``, live mode is still a dry run.

Nothing ambiguous is created. A user is flagged for a person to decide when:

* the Okta user is DEPROVISIONED, AD/LDAP-mastered (those arrive through
  Entra Connect / Cloud Sync), a service account, or has a status this
  script doesn't know;
* the UPN would be rejected by Entra (characters such as '+' or accents);
* two Okta users share a login or an email, or several Entra users share
  the email we'd match on;
* the UPN matches but names/email differ, or only the email matches
  (possible rename);
* the UPN domain isn't verified in the tenant, or is federated and the
  user has no source anchor to set onPremisesImmutableId from.

Okta status decides the new account's state (see STATUS_POLICY): people
who can sign in today (ACTIVE, LOCKED_OUT, PASSWORD_EXPIRED, RECOVERY) are
created enabled; STAGED, PROVISIONED and SUSPENDED users are created
disabled and get no Temporary Access Pass.

``--apply`` needs ``--expect-tenant <guid>`` and one of ``--tap-file``,
``--show-taps`` or ``--no-tap``, so a TAP is never printed somewhere you
didn't ask for. TAPs are never written into the JSON report or audit log.
Creation and TAP issuance are journaled separately, so a rerun retries a
failed TAP without touching the user, and a user created just before a
crash still gets its TAP.

Examples:
    python3 import_users.py                                  # dry run vs fixture
    python3 import_users.py --live --usage-location GB       # dry run vs Graph
    python3 import_users.py --live --apply --expect-tenant <guid> \\
        --tap-file taps.tsv
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from anchors import GUID_RE, immutable_id_from_guid  # noqa: E402
from audit import AuditLog  # noqa: E402
from entra_names import mail_nickname, upn_problem  # noqa: E402
from graph_api import GraphClient  # noqa: E402
from inventory import load_inventory  # noqa: E402
from journal import Journal, JournalMismatchError  # noqa: E402
from secure_io import atomic_write_text, write_json  # noqa: E402
from tenant_guard import check_graph_tenant, confirm_apply  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")
FIXTURE_ENTRA = os.path.join(os.path.dirname(__file__), "fixtures",
                             "entra-tenant.sample.json")

# Okta credential-provider types whose identities are mastered outside Okta.
AD_MASTERED_PROVIDERS = ("ACTIVE_DIRECTORY", "LDAP")

# Okta UserStatus -> (accountEnabled, issue TAP, note). DEPROVISIONED is
# handled separately (always flagged). Anything not listed is flagged.
STATUS_POLICY = {
    "ACTIVE": (True, True, "active in Okta"),
    "LOCKED_OUT": (True, True, "locked out in Okta (a sign-in lockout, "
                               "not an offboarding)"),
    "PASSWORD_EXPIRED": (True, True, "password expired in Okta; the TAP "
                                     "replaces it"),
    "RECOVERY": (True, True, "mid password reset in Okta"),
    "SUSPENDED": (False, False, "suspended in Okta; created disabled"),
    "STAGED": (False, False, "never activated in Okta; created disabled"),
    "PROVISIONED": (False, False, "activation pending in Okta; created "
                                  "disabled"),
}

# Okta base-profile attribute -> Graph user property written on create.
# Keep in step with rule_translator.ATTR_MAP so translated dynamic rules
# have data to match on.
PROFILE_TO_GRAPH = {
    "title": "jobTitle",
    "department": "department",
    "city": "city",
    "state": "state",
    "streetAddress": "streetAddress",
    "zipCode": "postalCode",
    "organization": "companyName",
    "employeeNumber": "employeeId",
    "mobilePhone": "mobilePhone",
}

COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")

MUTATION_POLICY = {
    "mode": "create-only",
    "setsOnCreate": [
        "accountEnabled (from Okta status, see statusPolicy)",
        "displayName", "mailNickname (sanitized)", "userPrincipalName",
        "mail", "givenName", "surname", "usageLocation (Okta countryCode, "
        "else --usage-location)", "onPremisesImmutableId (federated "
        "domains only, from --federated-anchor-attr)",
    ] + sorted(PROFILE_TO_GRAPH.values()) + [
        "passwordProfile (random value, never stored or reported)"],
    "neverUpdates": "users matched to an existing Entra account are "
                    "never modified",
    "neverImports": "flagged users are never imported",
    "neverDeletes": True,
}


def is_service_account(user: dict) -> bool:
    return user.get("userType") == "SERVICE" or \
        (user.get("login") or "").lower().startswith("svc_")


def _is_guest(eu: dict) -> bool:
    return (eu.get("userType") or "").lower() == "guest" or \
        "#ext#" in (eu.get("userPrincipalName") or "").lower()


def _okta_duplicates(okta_users: list[dict]) -> dict[str, str]:
    """okta user id -> reason, for logins/emails shared by several users."""
    by_login: dict[str, list] = {}
    by_email: dict[str, list] = {}
    for ou in okta_users:
        if ou.get("status") == "DEPROVISIONED":
            continue
        if ou.get("login"):
            by_login.setdefault(ou["login"].strip().lower(), []).append(ou)
        if ou.get("email"):
            by_email.setdefault(ou["email"].strip().lower(), []).append(ou)
    out: dict[str, str] = {}
    for label, idx in (("login", by_login), ("email", by_email)):
        for value, users in idx.items():
            if len(users) > 1:
                ids = ", ".join(u.get("id") or "?" for u in users)
                for u in users:
                    out.setdefault(u.get("id"), f"{len(users)} Okta users "
                                   f"share {label} {value!r} ({ids})")
    return out


def match_users(okta_users: list[dict], entra_users: list[dict]) -> dict:
    """Return {'matched', 'to_create', 'flagged'} buckets.

    Tier 1: exact UPN match. Tier 2: email match (possible UPN rename --
    flagged, never auto-merged). No match: would-create, unless a guard
    fires.
    """
    by_upn: dict[str, list] = {}
    by_email: dict[str, list] = {}
    for u in entra_users:
        if u.get("userPrincipalName"):
            by_upn.setdefault(u["userPrincipalName"].lower(), []).append(u)
        if u.get("mail") and not _is_guest(u):
            by_email.setdefault(u["mail"].lower(), []).append(u)
    dupes = _okta_duplicates(okta_users)
    matched, to_create, flagged = [], [], []

    for ou in okta_users:
        login = (ou.get("login") or "").strip()
        if not login:
            flagged.append({"user": ou, "reason": "no login/UPN in inventory"})
            continue
        status = ou.get("status")
        if status == "DEPROVISIONED":
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
        if ou.get("id") in dupes:
            flagged.append({"user": ou, "reason": dupes[ou["id"]]
                            + " -- decide which one is real first"})
            continue
        upn_hits = by_upn.get(login.lower(), [])
        if not upn_hits:
            email = (ou.get("email") or "").lower()
            em = by_email.get(email, []) if email else []
            if len(em) > 1:
                flagged.append({"user": ou, "reason":
                                f"UPN {login!r} not in Entra and "
                                f"{len(em)} Entra users share email "
                                f"{email!r} -- ambiguous, review"})
                continue
            if em:
                flagged.append({"user": ou, "entraUser": em[0],
                                "reason": f"UPN {login!r} not found in Entra "
                                          f"but email matches "
                                          f"{em[0].get('userPrincipalName')!r} "
                                          f"-- possible UPN rename; review "
                                          f"before merging"})
                continue
            if is_service_account(ou):
                flagged.append({"user": ou,
                                "reason": "service account -- handled by "
                                          "inventory_service_accounts.py, "
                                          "not by user import"})
                continue
            if status not in STATUS_POLICY:
                flagged.append({"user": ou, "reason":
                                f"Okta status {status!r} has no mapping "
                                f"-- review"})
                continue
            problem = upn_problem(login)
            if problem:
                flagged.append({"user": ou, "reason":
                                f"{problem} -- choose a new UPN for this "
                                f"user first"})
                continue
            to_create.append({"user": ou})
            continue
        eu = upn_hits[0]
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


def usage_location_for(okta_user: dict, default: str | None) -> str | None:
    cc = (okta_user.get("countryCode")
          or (okta_user.get("profile") or {}).get("countryCode") or "")
    if COUNTRY_RE.match(cc.strip()):
        return cc.strip().upper()
    return default


def entra_user_payload(okta_user: dict, usage_location: str | None = None,
                       immutable_id: str | None = None) -> dict:
    """Graph user body for a net-new user (no passwordProfile; the apply
    loop adds a random one that is never stored)."""
    login = okta_user["login"]
    profile = okta_user.get("profile") or {}
    enabled = STATUS_POLICY.get(okta_user.get("status"), (False,))[0]
    body = {
        "accountEnabled": enabled,
        "displayName": f"{okta_user.get('firstName') or ''} "
                       f"{okta_user.get('lastName') or ''}".strip() or login,
        "mailNickname": mail_nickname(login.split("@")[0]),
        "userPrincipalName": login,
        "mail": okta_user.get("email") or login,
        "givenName": okta_user.get("firstName"),
        "surname": okta_user.get("lastName"),
    }
    for okta_attr, graph_prop in PROFILE_TO_GRAPH.items():
        value = profile.get(okta_attr) or okta_user.get(okta_attr)
        if value not in (None, ""):
            body[graph_prop] = value
    if usage_location:
        body["usageLocation"] = usage_location
    if immutable_id:
        body["onPremisesImmutableId"] = immutable_id
    return {k: v for k, v in body.items() if v is not None}


def domain_preflight(buckets: dict, domains: list[dict], anchor_attr: str | None,
                     log) -> None:
    """Move users whose UPN domain can't take a cloud-created user to flagged.

    Unverified domains are rejected by Graph. Federated domains need
    onPremisesImmutableId on create (Learn, Create user); we set it when the
    user's profile has a GUID anchor in ``anchor_attr``, otherwise flag.
    """
    verified = {d.get("id", "").lower(): d for d in domains if d.get("isVerified")}
    kept = []
    for item in buckets["to_create"]:
        user = item["user"]
        domain = user["login"].split("@")[-1].lower()
        d = verified.get(domain)
        if d is None:
            buckets["flagged"].append({
                "user": user,
                "reason": f"UPN domain {domain!r} is not a verified domain in "
                          f"the Entra tenant -- verify the domain (or fix the "
                          f"UPN) before creating"})
            log(f"domain-preflight: skipping {user['login']} "
                f"(unverified domain {domain!r})")
            continue
        if (d.get("authenticationType") or "").lower() == "federated":
            anchor = (user.get("profile") or {}).get(anchor_attr or "")
            if anchor and GUID_RE.match(str(anchor).strip()):
                item["immutableId"] = immutable_id_from_guid(str(anchor))
            else:
                buckets["flagged"].append({
                    "user": user,
                    "reason": f"UPN domain {domain!r} is federated, so Entra "
                              f"needs onPremisesImmutableId to create this "
                              f"user. Let sync or the existing federation "
                              f"provisioning create it, convert the domain "
                              f"to managed first, or pass "
                              f"--federated-anchor-attr with a GUID anchor"})
                continue
        kept.append(item)
    buckets["to_create"] = kept


def report_text(buckets: dict) -> str:
    lines = [f"matched:      {len(buckets['matched'])}",
             f"would-create: {len(buckets['to_create'])}",
             f"flagged:      {len(buckets['flagged'])}"]
    disabled = [i for i in buckets["to_create"]
                if not STATUS_POLICY.get(i["user"].get("status"), (False,))[0]]
    if disabled:
        lines.append(f"  of which created disabled (Okta status not active): "
                     f"{len(disabled)}")
    no_loc = [i for i in buckets["to_create"] if not i.get("usageLocation")]
    if no_loc:
        lines.append(f"  without usageLocation (licences can't be assigned "
                     f"until it is set): {len(no_loc)}")
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
                   help="create missing users (requires --live and "
                        "--expect-tenant)")
    p.add_argument("--expect-tenant", metavar="GUID",
                   help="the Entra tenant id this run is meant for; the run "
                        "stops if the credentials point anywhere else")
    p.add_argument("--usage-location", metavar="CC",
                   help="two-letter country code for users whose Okta "
                        "profile has no countryCode (default: leave unset "
                        "and report them)")
    p.add_argument("--federated-anchor-attr", metavar="ATTR",
                   help="Okta profile attribute holding a GUID source anchor "
                        "(e.g. objectGUID); used to set onPremisesImmutableId "
                        "for users in federated domains")
    p.add_argument("--skip-inactive", action="store_true",
                   help="flag STAGED/PROVISIONED/SUSPENDED users instead of "
                        "creating them disabled")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive APPLY confirmation")
    p.add_argument("--audit-log", default="toolkit.audit.jsonl",
                   help="append-only audit trail of every write "
                        "(default: %(default)s)")
    tap = p.add_argument_group("Temporary Access Passes (with --apply)")
    tap.add_argument("--tap-file",
                     help="write issued TAPs to this file (0600)")
    tap.add_argument("--show-taps", action="store_true",
                     help="print issued TAPs to the terminal")
    tap.add_argument("--no-tap", action="store_true",
                     help="don't issue TAPs (use your own onboarding "
                          "credential)")
    tap.add_argument("--tap-lifetime", type=int, default=480,
                     help="TAP lifetime in minutes (10-43200, and within "
                          "the tenant's TAP policy; default %(default)s)")
    p.add_argument("--journal", default="import-users.journal.jsonl",
                   help="checkpoint journal for --apply, tied to the tenant "
                        "(default: %(default)s)")
    p.add_argument("--report", help="write JSON report to this path")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def _issue_tap(gc, args, audit, journal, login, entra_id, okta_id, taps, log):
    tkey = f"tap:{login}"
    try:
        tap = gc.create_temporary_access_pass(entra_id, args.tap_lifetime)
    except Exception as e:  # noqa: BLE001 - the user exists; retry later
        journal.record(tkey, "error", {"entraId": entra_id,
                                       "error": str(e)[:200]})
        log(f"WARNING: TAP failed for {login}: {e} -- rerun to retry")
        return False
    taps.append((login, tap.get("temporaryAccessPass") or ""))
    journal.record(tkey, "ok", {"entraId": entra_id, "tapId": tap.get("id")})
    audit.record("issue-tap", "temporaryAccessPass", tap.get("id"), login,
                 {"oktaId": okta_id})
    return True


def main(argv=None, graph_client=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    if args.usage_location and not COUNTRY_RE.match(args.usage_location):
        print("error: --usage-location must be a two-letter country code",
              file=sys.stderr)
        return 2
    if args.apply:
        if not args.live:
            print("error: --apply requires --live", file=sys.stderr)
            return 2
        if not args.expect_tenant:
            print("error: --apply requires --expect-tenant <tenant-guid>",
                  file=sys.stderr)
            return 2
        if not (args.tap_file or args.show_taps or args.no_tap):
            print("error: --apply needs --tap-file PATH, --show-taps or "
                  "--no-tap, so TAPs only go where you asked", file=sys.stderr)
            return 2
        if args.show_taps and args.quiet:
            print("error: --show-taps and --quiet contradict each other",
                  file=sys.stderr)
            return 2
        if not 10 <= args.tap_lifetime <= 43200:
            print("error: --tap-lifetime must be 10-43200 minutes",
                  file=sys.stderr)
            return 2
    default_loc = args.usage_location.upper() if args.usage_location else None

    inv = load_inventory(args.inventory)
    okta_users = inv["users"]

    if args.live:
        gc = graph_client or GraphClient()
        org = check_graph_tenant(gc, log, args.expect_tenant)
        if org is None:
            return 2
        entra_users = list(gc.list_users())
    else:
        org, gc = {}, None
        with open(args.entra_fixture, encoding="utf-8") as fh:
            entra_users = json.load(fh)["users"]

    buckets = match_users(okta_users, entra_users)
    if args.skip_inactive:
        kept = []
        for item in buckets["to_create"]:
            if STATUS_POLICY[item["user"]["status"]][0]:
                kept.append(item)
            else:
                buckets["flagged"].append({"user": item["user"], "reason":
                                           f"Okta status {item['user']['status']}"
                                           f" -- skipped (--skip-inactive)"})
        buckets["to_create"] = kept
    if args.live:
        domain_preflight(buckets, list(gc.list_domains()),
                         args.federated_anchor_attr, log)
    for item in buckets["to_create"]:
        u = item["user"]
        item["usageLocation"] = usage_location_for(u, default_loc)
        enabled, _, note = STATUS_POLICY[u["status"]]
        item["accountEnabled"] = enabled
        item["statusNote"] = note

    if args.apply:
        try:
            journal = Journal(args.journal, binding={
                "script": "import_users",
                "entraTenantId": (org.get("id") or "").lower(),
                "oktaSource": inv["source"].get("oktaOrgId")
                or inv["source"].get("oktaDomain")
                or inv["source"].get("rawFile") or "unknown"})
        except JournalMismatchError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
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
            "candidates": len(buckets["to_create"]), "journal": args.journal})
        taps: list[tuple[str, str]] = []
        n_created = n_failed = n_resumed = n_recovered = 0

        # A user created just before a crash shows up as "matched" with a
        # pending journal entry: finish its bookkeeping and TAP.
        for item in buckets["matched"]:
            login = item["user"]["login"]
            rec = journal.get(login)
            if rec and rec.get("status") == "pending":
                eid = item["entraUser"].get("id")
                enabled = STATUS_POLICY.get(item["user"].get("status"),
                                            (False, False))
                journal.record(login, "ok", {"entraId": eid,
                                             "accountEnabled": enabled[0],
                                             "recovered": True})
                n_recovered += 1
                log(f"recovered interrupted create: {login} -> {eid}")

        for item in buckets["to_create"]:
            user = item["user"]
            login = user["login"]
            if journal.completed(login):
                item["resumed"] = True
                n_resumed += 1
                log(f"resume-skip (already done): {login}")
                continue
            try:
                body = entra_user_payload(user, item["usageLocation"],
                                          item.get("immutableId"))
                body["passwordProfile"] = {
                    "forceChangePasswordNextSignIn": True,
                    "password": secrets.token_urlsafe(32)}
                journal.record(login, "pending")
                created = gc.create_user(body)
            except Exception as e:  # noqa: BLE001 - keep the batch going
                journal.record(login, "error", str(e)[:300])
                item["applyError"] = str(e)[:300]
                audit.record("create-user-failed", "user", "", login,
                             {"oktaId": user.get("id"), "error": str(e)[:200]})
                n_failed += 1
                log(f"ERROR creating {login}: {e} -- continuing")
                continue
            item["createdEntraId"] = created["id"]
            journal.record(login, "ok", {"entraId": created["id"],
                                         "accountEnabled": body["accountEnabled"]})
            audit.record("create-user", "user", created["id"], login,
                         {"oktaId": user.get("id"),
                          "accountEnabled": body["accountEnabled"]})
            n_created += 1
            log(f"created {login} -> {created['id']}"
                + ("" if body["accountEnabled"] else " (disabled)"))

        # TAP phase: every enabled user this journal created, whose TAP
        # isn't done yet (covers new users, earlier TAP failures and
        # recovered creates).
        if not args.no_tap:
            for key, rec in list(journal.records.items()):
                if key.startswith("tap:") or rec.get("status") != "ok":
                    continue
                detail = rec.get("detail") or {}
                if not detail.get("accountEnabled") or \
                        journal.completed(f"tap:{key}"):
                    continue
                _issue_tap(gc, args, audit, journal, key, detail.get("entraId"),
                           None, taps, log)
            for item in buckets["to_create"]:
                item["tapIssued"] = journal.completed(
                    f"tap:{item['user']['login']}")
        if taps and args.tap_file:
            atomic_write_text(args.tap_file,
                              "".join(f"{lg}\t{v}\n" for lg, v in taps),
                              mode=0o600)
            log(f"{len(taps)} TAP(s) written to {args.tap_file} (0600; "
                f"treat as secrets)")
        if taps and args.show_taps:
            for lg, v in taps:
                print(f"TAP for {lg}: {v}")
        log(f"apply done: {n_created} created, {n_failed} failed, "
            f"{n_resumed} resumed-skipped, {n_recovered} recovered, "
            f"{len(taps)} TAPs issued (journal: {args.journal})")
        audit.record("apply-done", detail={
            "created": n_created, "failed": n_failed, "resumed": n_resumed,
            "recovered": n_recovered, "taps": len(taps)})

    log(report_text(buckets))
    if args.report:
        # Scrubbed + 0600 + atomic: reports never carry secrets.
        write_json(args.report, {**buckets, "mutationPolicy": MUTATION_POLICY,
                                 "statusPolicy": {
                                     k: {"accountEnabled": v[0],
                                         "temporaryAccessPass": v[1],
                                         "note": v[2]}
                                     for k, v in STATUS_POLICY.items()}})
        log(f"report written to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
