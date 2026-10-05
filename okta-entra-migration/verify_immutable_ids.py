#!/usr/bin/env python3
"""LIFE-50: Verify ImmutableID / source-anchor alignment.

Before Microsoft Entra Connect (or Cloud Sync) is pointed at a tenant that
already holds user objects -- cloud users created by import_users.py, or
pre-existing ones -- every object's onPremisesImmutableId must equal the
Base64 form of its on-premises source anchor. If it doesn't, sync either
creates a duplicate or fails to hard-match, and for federated domains the
ImmutableID is also half of the SAML NameID claim. This script computes the
expected value from the Okta inventory and compares it with Entra.

Verified computation (not model folklore):
  - Microsoft Learn: the SourceAnchor value "is the Base64 string
    representation of the mS-Ds-ConsistencyGUID attribute (or ObjectGUID
    depending on the configuration) from the on-premises Active Directory
    object. This value is set as the corresponding ImmutableId in
    Microsoft Entra ID."
    (learn.microsoft.com -- Entra Connect: installing with an existing
    tenant, hard-match vs soft-match)
  - The canonical hard-match recalculation is the PowerShell
        $immutableID = [System.Convert]::ToBase64String($guid.ToByteArray())
    .NET Guid.ToByteArray() serializes the GUID fields little-endian, which
    is exactly Python's uuid.UUID(...).bytes_le.

Scope, honestly labeled:
  - GUID-form anchors only (objectGUID, ms-DS-ConsistencyGuid -- the
    documented cases). Non-GUID anchor values are flagged "bad-anchor" for
    manual verification; v1 does not guess their encoding.
  - Read-only. No --apply exists; nothing is written to Entra.
  - The anchor attribute name comes from --anchor-attr (default
    "objectGUID"). Point it at whatever your Okta AD-sourced profiles
    actually carry, and make sure it is the same attribute your Entra
    Connect uses as its sourceAnchor -- a mismatch there is itself a
    finding this script cannot see.

Verdicts per user:
  match                      Entra onPremisesImmutableId == expected
  mismatch                   differs -- enabling sync would hard-match the
                             wrong object or fail; investigate before sync
  entra-missing-immutableid  Entra user exists but has no ImmutableID
                             (cloud-only) -- pre-stage the expected value
                             before enabling sync, or expect soft-match
                             behavior
  no-entra-user              not in Entra (not yet imported/synced)
  no-anchor                  Okta profile lacks the anchor attribute
  bad-anchor                 anchor value is not GUID-form (v1 limitation)

Examples:
    python3 verify_immutable_ids.py
    python3 verify_immutable_ids.py --entra-fixture /tmp/entra.json
    python3 verify_immutable_ids.py --live --report /tmp/immutable.json
    python3 verify_immutable_ids.py --anchor-attr ms-DS-ConsistencyGuid --all-users
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.dirname(__file__))

from inventory import load_inventory  # noqa: E402
from secure_io import write_json  # noqa: E402

REPO = os.path.dirname(os.path.abspath(__file__))
FIXTURE_INV = os.path.join(REPO, "fixtures", "okta-inventory.sample.json")
FIXTURE_ENTRA = os.path.join(REPO, "fixtures", "entra-tenant.sample.json")

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

AD_PROVIDERS = {"ACTIVE_DIRECTORY", "LDAP"}


def immutable_id_from_guid(guid_str: str) -> str:
    """Expected Entra ImmutableID for a GUID-form source anchor.

    Base64 of the GUID bytes in .NET Guid.ToByteArray() order
    (little-endian fields == uuid.UUID.bytes_le). Raises ValueError for
    non-GUID input.
    """
    return base64.b64encode(
        uuid.UUID(guid_str.strip()).bytes_le).decode("ascii")


def verify_users(okta_users: list[dict], entra_users: list[dict],
                 anchor_attr: str, ad_only: bool = True) -> dict:
    """Compare expected ImmutableIDs against Entra's onPremisesImmutableId."""
    by_upn = {str(u.get("userPrincipalName") or "").lower(): u
              for u in entra_users if u.get("userPrincipalName")}
    by_mail = {str(u.get("mail") or "").lower(): u
               for u in entra_users if u.get("mail")}
    results: list[dict] = []
    skipped = 0
    for ou in okta_users:
        provider = str(ou.get("credentialProvider") or "").upper()
        if ad_only and provider not in AD_PROVIDERS:
            skipped += 1
            continue
        login = str(ou.get("login") or "")
        email = str(ou.get("email") or "")
        anchor = (ou.get("profile") or {}).get(anchor_attr)
        rec: dict = {"login": login, "oktaId": ou.get("id"),
                     "credentialProvider": ou.get("credentialProvider"),
                     "anchorAttr": anchor_attr, "anchorValue": anchor}
        if not anchor:
            rec["verdict"] = "no-anchor"
            rec["detail"] = (f"Okta profile has no {anchor_attr!r}; "
                             "cannot compute the expected ImmutableID")
        elif not GUID_RE.match(str(anchor).strip()):
            rec["verdict"] = "bad-anchor"
            rec["detail"] = ("anchor value is not GUID-form; v1 only "
                             "computes GUID anchors (objectGUID / "
                             "ms-DS-ConsistencyGuid) -- verify manually")
        else:
            expected = immutable_id_from_guid(str(anchor))
            rec["expectedImmutableId"] = expected
            eu = (by_upn.get(login.lower())
                  or by_mail.get(email.lower()))
            if eu is None:
                rec["verdict"] = "no-entra-user"
                rec["detail"] = ("no Entra user with this UPN/email; "
                                 "import or sync has not created it yet")
            else:
                actual = eu.get("onPremisesImmutableId")
                rec["entraId"] = eu.get("id")
                rec["entraUpn"] = eu.get("userPrincipalName")
                rec["actualImmutableId"] = actual
                if not actual:
                    rec["verdict"] = "entra-missing-immutableid"
                    rec["detail"] = ("Entra user is cloud-only (no "
                                     "ImmutableID); pre-stage the expected "
                                     "value before enabling sync")
                elif actual == expected:
                    rec["verdict"] = "match"
                    rec["detail"] = "hard-match will succeed"
                else:
                    rec["verdict"] = "mismatch"
                    rec["detail"] = ("Entra ImmutableID differs from the "
                                     "expected anchor value -- enabling "
                                     "sync risks a duplicate or a failed "
                                     "hard-match; investigate first")
        results.append(rec)
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"anchorAttr": anchor_attr, "adOnly": ad_only,
            "checked": len(results), "skippedNonAd": skipped,
            "counts": counts, "results": results}


def print_report(report: dict) -> None:
    print(f"ImmutableID verification (anchor attribute: "
          f"{report['anchorAttr']}, AD-mastered only: {report['adOnly']})")
    print(f"checked={report['checked']} "
          f"skipped_non_ad={report['skippedNonAd']}")
    for verdict, n in sorted(report["counts"].items()):
        print(f"  {verdict}: {n}")
    problems = [r for r in report["results"] if r["verdict"] != "match"]
    if problems:
        print("\nneeds attention:")
        for r in problems:
            print(f"  [{r['verdict']}] {r['login']}: {r.get('detail')}")
            if r.get("expectedImmutableId"):
                print(f"      expected: {r['expectedImmutableId']}")
                if r.get("actualImmutableId"):
                    print(f"      actual:   {r['actualImmutableId']}")
    else:
        print("all checked users match -- safe to enable sync")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Verify Entra onPremisesImmutableId against the "
                    "Okta-side source anchor (read-only).")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("--anchor-attr", default="objectGUID",
                   help="Okta profile attribute holding the AD anchor "
                        "(default: objectGUID; must be the same attribute "
                        "Entra Connect uses as its sourceAnchor)")
    p.add_argument("--live", action="store_true",
                   help="compare against Microsoft Graph (read-only)")
    p.add_argument("--entra-fixture",
                   help="local Entra user dump to compare against "
                        "(default: bundled fixture)")
    p.add_argument("--all-users", action="store_true",
                   help="check non-AD-mastered users too (default: "
                        "AD/LDAP-mastered only)")
    p.add_argument("--report",
                   help="write the JSON report to PATH (0600, atomic)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    inv = load_inventory(args.inventory)
    if args.live:
        from graph_api import GraphClient, TenantMismatchError  # noqa: E402
        from tenant_guard import check_graph_tenant  # noqa: E402
        try:
            g = GraphClient.from_env()
            org = check_graph_tenant(g)
        except (TenantMismatchError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"connected to tenant {org.get('displayName') or '?'} "
                  f"({org.get('id') or '?'}) -- read-only check")
        entra_users = g.list_user_anchors()
    else:
        import json  # noqa: E402
        path = args.entra_fixture or FIXTURE_ENTRA
        with open(path) as fh:
            entra_users = json.load(fh)["users"]
    report = verify_users(inv["users"], entra_users, args.anchor_attr,
                          ad_only=not args.all_users)
    if not args.quiet:
        print_report(report)
    if args.report:
        write_json(args.report, report)
        if not args.quiet:
            print(f"report written to {args.report}")
    bad = sum(n for v, n in report["counts"].items() if v != "match")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
