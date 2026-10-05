#!/usr/bin/env python3
"""Sign-on policy linter (DHQ-81). READ-ONLY.

Scans OKTA_SIGN_ON policies and their rules for weak configurations:

  (a) PASSWORD-ONLY: rules where actions.signon.requireFactor is false,
      i.e. the rule grants access with no MFA requirement.
  (b) DEVICE-ASSURANCE (heuristic): rules granting access whose conditions
      contain no mention of "device" (device trust / device assurance).
  (c) OVER-BROAD NETWORK ZONES: rules attached to network connection
      "ANYWHERE", or referencing gateway CIDRs with a prefix shorter than
      --min-zone-prefix (default 16), including 0.0.0.0/0.

Usage:
    export OKTA_DOMAIN=https://dev-123456.okta.com
    export OKTA_API_TOKEN=00...
    python scripts/python/sign_on_policy_linter.py
    python scripts/python/sign_on_policy_linter.py --min-zone-prefix 24
    python scripts/python/sign_on_policy_linter.py --limit 5
    python scripts/python/sign_on_policy_linter.py --json --output findings.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.okta_client import OktaClient, OktaAuthError


def signon_actions(rule: dict) -> dict:
    return rule.get("actions", {}).get("signon", {})


def grants_access(rule: dict) -> bool:
    """A rule that grants access is anything not explicitly DENY."""
    return signon_actions(rule).get("access") != "DENY"


def check_password_only(policy_name: str, rule: dict) -> dict | None:
    actions = signon_actions(rule)
    if grants_access(rule) and actions.get("requireFactor") is False:
        return {
            "policy": policy_name,
            "rule": rule.get("name"),
            "check": "password-only",
            "severity": "HIGH",
            "detail": (
                f"access={actions.get('access')}, requireFactor=false: "
                "rule grants access without any MFA requirement"
            ),
        }
    return None


def check_device_assurance(policy_name: str, rule: dict) -> dict | None:
    conditions = rule.get("conditions", {})
    if grants_access(rule) and "device" not in json.dumps(conditions).lower():
        return {
            "policy": policy_name,
            "rule": rule.get("name"),
            "check": "device-assurance",
            "severity": "LOW",
            "detail": (
                "heuristic: no 'device' mention in rule conditions; "
                "consider a device-trust / device-assurance condition"
            ),
        }
    return None


def zone_gateways(zone: dict) -> list:
    """Return the CIDR gateway values for an IP network zone."""
    cidrs = []
    for gw in zone.get("gateways", []) or []:
        if gw.get("type") == "CIDR" and gw.get("value"):
            cidrs.append(gw["value"])
    return cidrs


def check_network_zones(policy_name: str, rule: dict, zones: dict,
                         min_prefix: int) -> list:
    findings = []
    if not grants_access(rule):
        return findings
    network = rule.get("conditions", {}).get("network", {})
    if network.get("connection") == "ANYWHERE":
        findings.append({
            "policy": policy_name,
            "rule": rule.get("name"),
            "check": "network-zone",
            "severity": "MEDIUM",
            "detail": "rule attached to network connection ANYWHERE",
        })
    for zone_id in network.get("include", []) or []:
        zone = zones.get(zone_id)
        if zone is None:
            continue
        for cidr in zone_gateways(zone):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if str(net) == "0.0.0.0/0" or net.prefixlen < min_prefix:
                findings.append({
                    "policy": policy_name,
                    "rule": rule.get("name"),
                    "check": "network-zone",
                    "severity": "HIGH" if net.prefixlen == 0 else "MEDIUM",
                    "detail": (
                        f"zone '{zone.get('name')}' includes CIDR {net} "
                        f"(prefix {net.prefixlen} < minimum {min_prefix})"
                    ),
                })
    return findings


def lint(client: OktaClient, limit: int = 0, min_prefix: int = 16,
         progress_every: int = 10):
    findings = []
    zones = {z.get("id"): z for z in client.list_zones()}
    policies = list(client.list_policies("OKTA_SIGN_ON"))
    for n, policy in enumerate(policies, 1):
        if limit and n > limit:
            break
        policy_name = policy.get("name")
        for rule in client.list_policy_rules(policy.get("id")):
            for finding in (
                check_password_only(policy_name, rule),
                check_device_assurance(policy_name, rule),
            ):
                if finding:
                    findings.append(finding)
            findings.extend(check_network_zones(policy_name, rule, zones,
                                                min_prefix))
        if n % progress_every == 0:
            print(f"... linted {n} policies", file=sys.stderr)
    return findings, len(policies)


def print_table(findings: list):
    print(f"{'POLICY':28} {'RULE':28} {'CHECK':16} {'SEV':6} DETAIL")
    print("-" * 130)
    for f in findings:
        print(f"{(f['policy'] or '')[:28]:28} {(f['rule'] or '')[:28]:28} "
              f"{f['check'][:16]:16} {f['severity']:6} {f['detail']}")


def main():
    p = argparse.ArgumentParser(
        description="Lint OKTA_SIGN_ON policies for weak auth configurations. READ-ONLY.")
    p.add_argument("--limit", type=int, default=0,
                   help="only lint N policies (0 = all)")
    p.add_argument("--min-zone-prefix", type=int, default=16,
                   help="flag gateway CIDRs with a prefix shorter than this (default 16)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--output", default=None, help="write report to file")
    args = p.parse_args()

    try:
        client = OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    findings, policy_count = lint(client, limit=args.limit,
                                 min_prefix=args.min_zone_prefix)

    severities = {}
    for f in findings:
        severities[f["severity"]] = severities.get(f["severity"], 0) + 1
    summary = {"policies_linted": policy_count, "findings": len(findings),
               **severities}

    if args.json:
        report = json.dumps({"summary": summary, "findings": findings}, indent=2)
    else:
        print_table(findings)
        sev = ", ".join(f"{k}: {v}" for k, v in sorted(severities.items()))
        report_lines = [
            "",
            f"Policies: {summary['policies_linted']} | "
            f"findings: {summary['findings']}"
            + (f" ({sev})" if sev else ""),
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
