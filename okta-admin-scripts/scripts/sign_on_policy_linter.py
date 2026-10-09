#!/usr/bin/env python3
"""Lint Okta sign-on policy rules for weak settings (read-only).

Checks, using fields that exist in the policy rule schemas:

    no-mfa (OKTA_SIGN_ON rules)
        actions.signon.access ALLOW with requireFactor false. On Classic
        orgs this means password-only sign-in: HIGH. On Identity Engine
        orgs OKTA_SIGN_ON is the global session policy and MFA is usually
        enforced per app in ACCESS_POLICY rules, so it is reported as INFO.

    one-factor (ACCESS_POLICY rules, Identity Engine)
        actions.appSignOn.access ALLOW with verificationMethod.factorMode
        1FA: MEDIUM. Rules that only apply to password-recovery requests are
        skipped because one factor is normal there.

    network-anywhere / wide-zone
        A rule allowing access from ANYWHERE (LOW, it is Okta's default), or
        whose included network zone has a CIDR gateway wider than
        --min-zone-prefix (MEDIUM, HIGH for 0.0.0.0/0).

The engine is detected by whether the org has any ACCESS_POLICY policies.

Examples:
    python scripts/sign_on_policy_linter.py
    python scripts/sign_on_policy_linter.py --min-zone-prefix 24 --json
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.common import connect
from lib.okta_client import OktaApiError
from lib.output import emit, table


def finding(policy, rule, check, severity, detail) -> dict:
    return {"policy": policy.get("name"), "policy_type": policy.get("type"),
            "rule": rule.get("name"), "check": check, "severity": severity,
            "detail": detail}


def check_global_session_rule(policy: dict, rule: dict, oie: bool) -> list[dict]:
    signon = (rule.get("actions") or {}).get("signon") or {}
    if signon.get("access") == "ALLOW" and signon.get("requireFactor") is False:
        if oie:
            return [finding(policy, rule, "no-mfa", "INFO",
                            "global session rule does not require MFA; make sure "
                            "app sign-in policies do")]
        return [finding(policy, rule, "no-mfa", "HIGH",
                        "rule allows sign-in with a password only")]
    return []


def _is_recovery_only(rule: dict) -> bool:
    cond = (((rule.get("conditions") or {}).get("elCondition") or {}).get("condition") or "")
    return "accessRequest.operation=='recover'" in cond.replace(" ", "")


def check_app_sign_in_rule(policy: dict, rule: dict) -> list[dict]:
    app = (rule.get("actions") or {}).get("appSignOn") or {}
    method = app.get("verificationMethod") or {}
    if (app.get("access") == "ALLOW" and method.get("factorMode") == "1FA"
            and not _is_recovery_only(rule)):
        return [finding(policy, rule, "one-factor", "MEDIUM",
                        "app sign-in rule allows access with one factor")]
    return []


def zone_cidrs(zone: dict) -> list[str]:
    return [g["value"] for g in (zone.get("gateways") or [])
            if g.get("type") == "CIDR" and g.get("value")]


def check_network(policy: dict, rule: dict, zones: dict, min_prefix: int) -> list[dict]:
    actions = rule.get("actions") or {}
    access = ((actions.get("signon") or actions.get("appSignOn") or {}).get("access"))
    if access != "ALLOW":
        return []
    network = (rule.get("conditions") or {}).get("network") or {}
    out = []
    if network.get("connection") == "ANYWHERE":
        out.append(finding(policy, rule, "network-anywhere", "LOW",
                           "rule applies from any network"))
    for zone_id in network.get("include") or []:
        zone = zones.get(zone_id)
        if not zone:
            continue
        for cidr in zone_cidrs(zone):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.prefixlen < min_prefix:
                out.append(finding(policy, rule, "wide-zone",
                                   "HIGH" if net.prefixlen == 0 else "MEDIUM",
                                   f"zone '{zone.get('name')}' includes {net}"))
    return out


def lint(client, min_prefix: int = 16) -> tuple[list[dict], dict]:
    zones = {z.get("id"): z for z in client.list_zones()}
    try:
        access_policies = list(client.list_policies("ACCESS_POLICY"))
    except OktaApiError:
        access_policies = []  # Classic orgs reject the type
    oie = bool(access_policies)
    findings = []
    policies = [(p, "OKTA_SIGN_ON") for p in client.list_policies("OKTA_SIGN_ON")]
    policies += [(p, "ACCESS_POLICY") for p in access_policies]
    for policy, ptype in policies:
        for rule in client.list_policy_rules(policy["id"]):
            if rule.get("status") == "INACTIVE":
                continue
            if ptype == "OKTA_SIGN_ON":
                findings += check_global_session_rule(policy, rule, oie)
            else:
                findings += check_app_sign_in_rule(policy, rule)
            findings += check_network(policy, rule, zones, min_prefix)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["policy"] or ""))
    return findings, {"engine": "Identity Engine" if oie else "Classic",
                      "policies": len(policies)}


def main(argv=None):
    p = argparse.ArgumentParser(description="Lint Okta sign-on and app sign-in "
                                "policy rules (read-only).")
    p.add_argument("--min-zone-prefix", type=int, default=16,
                   help="flag zone CIDRs wider than this prefix (default 16)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--output", help="write the report here (.csv for CSV)")
    args = p.parse_args(argv)

    findings, meta = lint(connect(), args.min_zone_prefix)
    text = table([("SEV", 6), ("POLICY", 28), ("RULE", 28), ("CHECK", 16), ("DETAIL", 0)],
                 [[f["severity"], f["policy"], f["rule"], f["check"], f["detail"]]
                  for f in findings])
    text += f"\n\n{meta['engine']}: {meta['policies']} policies, {len(findings)} findings"
    emit(report={"summary": {**meta, "findings": len(findings)}, "findings": findings},
         text=text, as_json=args.json, output=args.output, csv_rows=findings)


if __name__ == "__main__":
    main()
