#!/usr/bin/env python3
"""LIFE-42: Mirror Okta groups in Entra ID and convert dynamic group rules.

Default (offline) mode reads the inventory contract and emits a group plan
(JSON): for each Okta group, the Entra group to create, which members it
would carry, and a translated Entra dynamic-membership rule. Okta rule
expressions that cannot be translated are flagged for human rewrite -- never
silently dropped.

Supported Okta expression subset (dynamic group rules):
    user.<attr> == "value", user.<attr> != "value",
    user.<attr> startsWith "value" / endsWith / contains,
    String.stringContains(user.<attr>, "value"),
    combined with && / || and parentheses, plus !( ... ).

Attr map (Okta profile -> Entra user attribute):
    department->department, title->jobTitle, city->city, country->country,
    employeeType->employeeType, division->division, office->physicalDeliveryOfficeName,
    manager->manager (not dynamic-eligible in Entra: flagged).

Live mode (``--live --apply``) creates the groups via Microsoft Graph
(GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET); dry run otherwise.

Examples:
    python3 mirror_groups.py                          # offline plan vs fixture
    python3 mirror_groups.py -o group-plan.json       # save plan
    python3 mirror_groups.py --live --apply           # create groups in Entra
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from inventory import load_inventory, by_id  # noqa: E402
from graph_api import GraphClient  # noqa: E402
from secure_io import write_json  # noqa: E402
from journal import Journal  # noqa: E402
from audit import AuditLog  # noqa: E402
from tenant_guard import check_graph_tenant, confirm_apply  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

# Okta profile attribute -> Entra user attribute.
ATTR_MAP = {
    "department": "department",
    "title": "jobTitle",
    "city": "city",
    "country": "country",
    "state": "state",
    "countryCode": "country",
    "employeeType": "employeeType",
    "division": "division",
    "office": "physicalDeliveryOfficeName",
    "costCenter": "costCenter",
    "company": "companyName",
}

# Entra supports a fixed set of user attributes in dynamic membership rules.
ENTRA_DYNAMIC_ATTRS = set(ATTR_MAP.values())

# Machine-readable stamp linking a mirrored Entra group back to its Okta
# group id. Entra allows duplicate displayNames, so name matching alone
# cannot prove identity -- the stamp is the id-based existence check.
OKTA_STAMP_RE = re.compile(r"\[okta-group-id:([^\]]+)\]")


def stamp_description(description: str | None, okta_group_id: str) -> str:
    """Append the Okta-group-id stamp to an Entra group description."""
    base = (description or "").strip()
    stamp = f"[okta-group-id:{okta_group_id}]"
    if stamp in base:
        return base
    return f"{base} {stamp}".strip()


def extract_stamped_id(description: str | None) -> str | None:
    """Return the Okta group id stamped in an Entra group description."""
    m = OKTA_STAMP_RE.search(description or "")
    return m.group(1) if m else None


class RuleTranslator:
    """Translate a subset of Okta group-rule expressions to Entra syntax."""

    def __init__(self):
        self.problems: list[str] = []

    # -- tokenizer ------------------------------------------------------

    _TOK = re.compile(r"""
        (?P<ws>\s+)
      | (?P<str>"(?:[^"\\]|\\.)*")
      | (?P<op>==|!=|&&|\|\||!|\(|\)|,|\.)
      | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
    """, re.VERBOSE)

    def _tokenize(self, expr: str):
        toks = []
        for m in self._TOK.finditer(expr):
            kind = m.lastgroup
            val = m.group(0)
            if kind == "ws":
                continue
            toks.append((kind, val))
        # Bail if any character wasn't consumed (unknown syntax).
        joined = "".join(t[1] for t in toks)
        squished = re.sub(r"\s+", "", expr)
        if joined != squished:
            self.problems.append(f"unparseable fragment near {squished!r}")
            return None
        return toks

    # -- recursive descent parser over the token stream ------------------

    def translate(self, expr: str) -> str | None:
        self.problems = []
        if not expr or not expr.strip():
            self.problems.append("empty rule expression")
            return None
        toks = self._tokenize(expr)
        if toks is None:
            return None
        self.toks = toks
        self.pos = 0
        try:
            out = self._or()
        except ValueError as e:
            self.problems.append(str(e))
            return None
        if self.pos != len(self.toks):
            self.problems.append("trailing tokens after expression")
            return None
        return out

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def _next(self):
        t = self._peek()
        self.pos += 1
        return t

    def _expect(self, val: str):
        kind, tok = self._next()
        if tok != val:
            raise ValueError(f"expected {val!r}, got {tok!r}")

    def _or(self):
        left = self._and()
        while self._peek()[1] == "||":
            self._next()
            left = f"({left} or {self._and()})"
        return left

    def _and(self):
        left = self._unary()
        while self._peek()[1] == "&&":
            self._next()
            left = f"({left} and {self._unary()})"
        return left

    def _unary(self):
        if self._peek()[1] == "!":
            self._next()
            return f"(not {self._operand()})"
        return self._operand()

    def _operand(self):
        if self._peek()[1] == "(":
            self._next()
            out = self._or()
            self._expect(")")
            return out
        return self._comparison()

    def _attr(self) -> str:
        kind, tok = self._next()
        if tok != "user":
            raise ValueError(f"only user.<attr> supported, got {tok!r}")
        self._expect(".")
        kind, attr = self._next()
        if kind != "word":
            raise ValueError(f"expected attribute name, got {attr!r}")
        mapped = ATTR_MAP.get(attr)
        if not mapped:
            raise ValueError(f"no Entra mapping for Okta attribute {attr!r}")
        if mapped not in ENTRA_DYNAMIC_ATTRS:
            raise ValueError(f"{mapped!r} not usable in Entra dynamic rules")
        return mapped

    def _string(self) -> str:
        kind, tok = self._next()
        if kind != "str":
            raise ValueError(f"expected string literal, got {tok!r}")
        return tok  # keep quotes; both syntaxes use double quotes

    def _comparison(self):
        # Forms: user.x == "v" | user.x != "v" |
        #        user.x startsWith "v" / endsWith / contains |
        #        String.stringContains(user.x, "v")
        kind, tok = self._peek()
        if tok == "String":
            self._next()
            self._expect(".")
            k2, fn = self._next()
            if fn != "stringContains":
                raise ValueError(f"unsupported String function {fn!r}")
            self._expect("(")
            attr = self._attr()
            self._expect(",")
            val = self._string()
            self._expect(")")
            return f'(user.{attr} -contains {val})'
        attr = self._attr()
        kind, op = self._peek()
        if op in ("==", "!="):
            self._next()
            val = self._string()
            return f'(user.{attr} -eq {val})' if op == "==" \
                else f'(user.{attr} -ne {val})'
        if op in ("startsWith", "endsWith", "contains"):
            self._next()
            val = self._string()
            entra_op = {"startsWith": "-startsWith", "endsWith": "-endsWith",
                        "contains": "-contains"}[op]
            return f"(user.{attr} {entra_op} {val})"
        raise ValueError(f"unsupported operator {op!r} on user.{attr}")


def plan_groups(inv: dict) -> dict:
    """Build the mirror plan for every inventory group."""
    users = by_id(inv["users"])
    translator = RuleTranslator()
    plan = {"groups": [], "untranslatedRules": []}
    for g in inv["groups"]:
        t = RuleTranslator()
        rule_src = g.get("dynamicRule")
        rule_entra = t.translate(rule_src) if rule_src else None
        entry = {
            "oktaGroupId": g["id"],
            "name": g["name"],
            "description": g.get("description", ""),
            "entraGroup": {
                "displayName": g["name"],
                # Stamped so later runs can prove this Entra group is the
                # mirror of this Okta group (displayNames are not unique).
                "description": stamp_description(
                    g.get("description", ""), g["id"]),
                "mailEnabled": False,
                "securityEnabled": True,
                "groupTypes": ["DynamicMembership"] if rule_entra else [],
                "membershipRule": rule_entra,
            },
            "memberCount": len(g.get("members", [])),
            "members": [users[m]["login"] for m in g.get("members", [])
                        if m in users and users[m].get("login")],
            "oktaRule": rule_src,
            "ruleProblems": t.problems,
        }
        if rule_src and not rule_entra:
            plan["untranslatedRules"].append({
                "group": g["name"], "oktaRule": rule_src,
                "problems": t.problems,
                "action": "REWRITE MANUALLY -- do not silently drop",
            })
        plan["groups"].append(entry)
    return plan


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Plan (or apply) mirroring Okta groups into Entra, "
                    "translating dynamic rules; untranslatable rules are "
                    "flagged, never dropped.")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("-o", "--output", help="write plan JSON to this path")
    p.add_argument("--live", action="store_true",
                   help="check Entra via Microsoft Graph "
                        "(GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET)")
    p.add_argument("--apply", action="store_true",
                   help="create missing groups in Entra (requires --live; "
                        "asks for confirmation unless --yes)")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive APPLY confirmation "
                        "(for automation; you own the consequences)")
    p.add_argument("--audit-log", default="toolkit.audit.jsonl",
                   help="append-only audit trail of every mutation "
                        "(default: %(default)s)")
    p.add_argument("--journal", default="mirror-groups.journal.jsonl",
                   help="checkpoint journal for --apply: a rerun skips groups "
                        "already ok/skipped and retries errors "
                        "(default: %(default)s)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    inv = load_inventory(args.inventory)
    plan = plan_groups(inv)

    log(f"{len(plan['groups'])} groups planned")
    for u in plan["untranslatedRules"]:
        log(f"  !! {u['group']}: rule needs manual rewrite: "
            f"{u['oktaRule']!r} ({'; '.join(u['problems'])})")

    if args.apply:
        if not args.live:
            print("error: --apply requires --live", file=sys.stderr)
            return 2
        gc = GraphClient()
        org = check_graph_tenant(gc, log)
        if org is None:
            return 2
        journal = Journal(args.journal)
        summary = (
            f"About to create up to {len(plan['groups'])} group(s) in Entra "
            f"tenant {org.get('displayName') or '?'} ({org.get('id') or '?'}).\n"
            f"Journal: {args.journal}  |  Audit log: {args.audit_log}\n"
            f"Name collisions are flagged, never auto-created.")
        if not confirm_apply(summary, args.yes):
            print("aborted -- nothing was created", file=sys.stderr)
            return 1
        audit = AuditLog(args.audit_log, script="mirror_groups",
                         tenant=org.get("id", ""))
        audit.record("apply-start", detail={
            "candidates": len(plan["groups"]), "journal": args.journal})
        # Id-based existence ledger: an Entra group counts as "already
        # mirrored" only if its description carries this Okta group's id
        # stamp. A bare displayName match is a collision to flag -- Entra
        # allows duplicate displayNames, so a name match proves nothing.
        stamped: dict[str, dict] = {}
        by_name: dict[str, list] = {}
        for eg in gc.list_groups():
            sid = extract_stamped_id(eg.get("description"))
            if sid:
                stamped[sid] = eg
            by_name.setdefault(
                (eg.get("displayName") or "").lower(), []).append(eg)
        collisions = []
        n_created = n_failed = n_resumed = 0
        for entry in plan["groups"]:
            key = entry["oktaGroupId"]
            if journal.completed(key):
                n_resumed += 1
                log(f"resume-skip (already done): {entry['name']}")
                continue
            try:
                hit = stamped.get(key)
                if hit is not None:
                    journal.record(
                        key, "skipped",
                        f"already mirrored as Entra group {hit.get('id')}")
                    log(f"skip (already mirrored): {entry['name']}")
                    continue
                dupes = by_name.get(entry["name"].lower(), [])
                if dupes:
                    # Never silently skip or auto-rename: the operator
                    # decides which Entra group (if any) is the real mirror.
                    collisions.append({
                        "oktaGroupId": key,
                        "name": entry["name"],
                        "entraMatches": [
                            {"id": d.get("id"),
                             "displayName": d.get("displayName"),
                             "description": d.get("description")}
                            for d in dupes],
                    })
                    log(f"COLLISION: Entra already has {len(dupes)} "
                        f"group(s) named {entry['name']!r} with no Okta-id "
                        f"stamp -- flagged for review, not created")
                    continue
                created = gc.create_group(entry["entraGroup"])
                journal.record(key, "ok", {"entraId": created.get("id")})
                audit.record("create-group", "group", created.get("id"),
                             entry["name"], {"oktaId": key})
                n_created += 1
                log(f"created {entry['name']} -> {created.get('id')}")
            except Exception as e:
                # One bad group must not abort the batch; the journal lets
                # a rerun retry exactly the failures.
                journal.record(key, "error", str(e)[:300])
                audit.record("create-group-failed", "group", "", entry["name"],
                             {"oktaId": key, "error": str(e)[:200]})
                n_failed += 1
                log(f"ERROR creating {entry['name']}: {e} -- continuing")
        if collisions:
            log(f"\nNAME COLLISIONS NEEDING REVIEW ({len(collisions)}):")
            for c in collisions:
                ids = ", ".join(m["id"] for m in c["entraMatches"])
                log(f"  - {c['name']} (okta {c['oktaGroupId']}): "
                    f"Entra group(s) {ids}")
            log("Resolve each collision (rename, stamp, or delete the "
                "duplicate), then rerun -- these were NOT created.")
        log(f"apply done: {n_created} created, {n_failed} failed, "
            f"{n_resumed} resumed-skipped, {len(collisions)} collisions "
            f"(journal: {args.journal})")
        audit.record("apply-done", detail={
            "created": n_created, "failed": n_failed,
            "resumed": n_resumed, "collisions": len(collisions)})

    if args.output:
        write_json(args.output, plan)  # scrubbed + 0600 + atomic
        log(f"plan written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
