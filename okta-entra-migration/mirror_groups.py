#!/usr/bin/env python3
"""Plan, and optionally create, Entra groups that mirror Okta groups.

For each Okta group the plan picks one of three outcomes:

* dynamic -- every active Okta group rule targeting the group translates
  to an Entra dynamic membership rule, the rules have no user/group
  exclusions, and every current member is explained by the rules. The
  Entra group gets the rules OR-ed together. (Entra dynamic groups can't
  hold manually added members, so a group with direct members can't be
  dynamic.)
* static -- no rules, or rules that can't be carried over. The Entra group
  is a plain security group and the current Okta members are written into
  it. When rules were involved, a manual item says the membership is now a
  snapshot that won't update on its own.
* skip -- Okta built-in groups (Everyone, Okta Administrators) and
  APP_GROUP groups that come from a directory or app integration.

Okta rule expressions are translated by lib/rule_translator.py; anything it
can't translate is listed with the reason, never dropped.

``--live --apply`` creates the groups through Microsoft Graph with a
sanitized, unique mailNickname and an owner (``--owner-id``), then adds
static members in batches of 20. It requires ``--expect-tenant``. Each
group and each group's membership is journaled separately, so a rerun picks
up where it stopped. Membership writes diff against what's already in the
group, so reruns don't fail on existing members.

Examples:
    python3 mirror_groups.py                          # offline plan vs fixture
    python3 mirror_groups.py -o group-plan.json
    python3 mirror_groups.py --live --apply \\
        --expect-tenant <tenant-guid> --owner-id <object-id>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from audit import AuditLog  # noqa: E402
from entra_names import mail_nickname  # noqa: E402
from graph_api import (MAX_MEMBERS_PER_PATCH, GraphClient,  # noqa: E402
                       GraphRequestError)
from inventory import by_id, load_inventory  # noqa: E402
from journal import Journal, JournalMismatchError  # noqa: E402
from rule_translator import (MAX_ENTRA_RULE_LENGTH, combine_or,  # noqa: E402
                             evaluate, translate)
from secure_io import write_json  # noqa: E402
from tenant_guard import check_graph_tenant, confirm_apply  # noqa: E402

FIXTURE_INV = os.path.join(os.path.dirname(__file__), "fixtures",
                           "okta-inventory.sample.json")

# Machine-readable stamp linking a mirrored Entra group back to its Okta
# group id. Entra allows duplicate displayNames, so a name match can't
# prove identity. The stamp lives in the description, which anyone with
# group write access can edit; treat it as a convenience, not a control.
OKTA_STAMP_RE = re.compile(r"\[okta-group-id:([^\]]+)\]")

SKIP_REASONS = {
    "BUILT_IN": "Okta built-in group. For an all-members group in Entra use "
                "a dynamic rule such as (user.objectId -ne null) -and "
                "(user.userType -eq \"Member\"), or leave it out.",
    "APP_GROUP": "Group imported from a directory or app integration. It "
                 "should reach Entra through sync or that app's "
                 "provisioning, not be recreated by hand.",
}


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


def _rules_for_inventory(inv: dict) -> dict[str, list]:
    """group id -> list of contract rules. Falls back to the older
    single-expression ``dynamicRule`` field when groupRules is absent."""
    by_group: dict[str, list] = {}
    rules = inv.get("groupRules") or []
    if rules:
        for r in rules:
            for gid in r.get("targetGroupIds") or []:
                by_group.setdefault(gid, []).append(r)
        return by_group
    for g in inv.get("groups", []):
        if g.get("dynamicRule"):
            by_group[g["id"]] = [{
                "id": f"legacy-{g['id']}", "name": None,
                "status": g.get("dynamicRuleStatus") or "ACTIVE",
                "expression": g["dynamicRule"], "targetGroupIds": [g["id"]],
                "excludedUserIds": [], "excludedGroupIds": []}]
    return by_group


def plan_groups(inv: dict, rule_state: str = "On") -> dict:
    """Build the mirror plan for every inventory group."""
    users = by_id(inv["users"])
    rules_by_group = _rules_for_inventory(inv)
    plan = {"groups": [], "untranslatedRules": [], "manualItems": [],
            "notes": []}

    for g in inv["groups"]:
        gid = g["id"]
        member_ids = list(g.get("members", []))
        live_members = [m for m in member_ids if m in users
                        and users[m].get("status") != "DEPROVISIONED"]
        entry = {
            "oktaGroupId": gid,
            "name": g["name"],
            "description": g.get("description", ""),
            "oktaType": g.get("type", "OKTA_GROUP"),
            "mode": "static",
            "reason": "",
            "memberCount": len(member_ids),
            "members": [users[m]["login"] for m in live_members
                        if users[m].get("login")],
            "rules": [],
            "oktaRule": g.get("dynamicRule"),
            "ruleProblems": [],
            "entraGroup": None,
        }
        plan["groups"].append(entry)

        if entry["oktaType"] in SKIP_REASONS:
            entry["mode"] = "skip"
            entry["reason"] = SKIP_REASONS[entry["oktaType"]]
            entry["members"] = []
            continue

        rules = rules_by_group.get(gid, [])
        active = [r for r in rules if r.get("status") == "ACTIVE"]
        for r in rules:
            if r.get("status") != "ACTIVE":
                entry["rules"].append({"id": r.get("id"),
                                       "okta": r.get("expression"),
                                       "status": r.get("status"),
                                       "ignored": "rule is not ACTIVE"})
        translations = []
        blockers = []
        for r in active:
            t = translate(r.get("expression") or "")
            translations.append(t)
            entry["rules"].append({"id": r.get("id"), "okta": t.okta,
                                   "entra": t.entra, "problems": t.problems,
                                   "notes": t.notes, "status": "ACTIVE"})
            entry["ruleProblems"].extend(t.problems)
            if not t.ok:
                blockers.append(f"rule {r.get('id')}: {'; '.join(t.problems)}")
                plan["untranslatedRules"].append({
                    "group": g["name"], "ruleId": r.get("id"),
                    "oktaRule": t.okta, "problems": t.problems,
                    "action": "rewrite by hand"})
            if r.get("excludedUserIds") or r.get("excludedGroupIds"):
                blockers.append(f"rule {r.get('id')} excludes specific users "
                                f"or groups, which an Entra rule can't express")

        if active and not blockers:
            asts = [t.ast for t in translations]
            unexplained = [
                m for m in live_members
                if not any(evaluate(a, users[m].get("profile") or {})
                           for a in asts)]
            unknown = [m for m in member_ids if m not in users]
            if unexplained or unknown:
                blockers.append(
                    f"{len(unexplained) + len(unknown)} current member(s) "
                    f"aren't explained by the rules (direct assignments or "
                    f"users missing from the export); an Entra dynamic "
                    f"group can't hold them")
            body = combine_or(translations)
            if len(body) > MAX_ENTRA_RULE_LENGTH:
                blockers.append(f"combined rule is {len(body)} characters; "
                                f"Entra allows {MAX_ENTRA_RULE_LENGTH}")

        payload = {
            "displayName": g["name"],
            "description": stamp_description(g.get("description", ""), gid),
            "mailEnabled": False,
            "mailNickname": mail_nickname(g["name"], gid),
            "securityEnabled": True,
            "groupTypes": [],
        }
        if active and not blockers:
            entry["mode"] = "dynamic"
            entry["reason"] = (f"{len(active)} active rule(s) translated; "
                               f"all current members match")
            payload["groupTypes"] = ["DynamicMembership"]
            payload["membershipRule"] = combine_or(translations)
            payload["membershipRuleProcessingState"] = rule_state
            entry["members"] = []
        elif active:
            entry["reason"] = ("rules can't be carried over: "
                               + " | ".join(blockers))
            plan["manualItems"].append({
                "kind": "group-rule",
                "group": g["name"], "oktaGroupId": gid,
                "what": "Membership will be a one-time snapshot of the Okta "
                        "group and won't update on its own. Rebuild the "
                        "logic as an Entra dynamic group, an access package, "
                        "or keep it static on purpose.",
                "why": blockers})
        else:
            entry["reason"] = "no active group rules; members copied as-is"
        entry["entraGroup"] = payload

    if any(e["mode"] == "dynamic" for e in plan["groups"]):
        plan["notes"].append(
            "Dynamic membership groups need a Microsoft Entra ID P1 licence "
            "(or Intune for Education) for every user who ends up in one.")
        plan["notes"].append(
            "Dynamic rules apply to every user in the tenant, including "
            "accounts that didn't come from Okta. Check who else matches "
            "before relying on a dynamic group for access.")
    counts: dict[str, int] = {}
    for e in plan["groups"]:
        counts[e["mode"]] = counts.get(e["mode"], 0) + 1
    plan["summary"] = counts
    return plan


# ---------------------------------------------------------------- apply

def _index_entra_users(entra_users) -> dict[str, list]:
    idx: dict[str, list] = {}
    for u in entra_users:
        upn = (u.get("userPrincipalName") or "").lower()
        if upn:
            idx.setdefault(upn, []).append(u)
    return idx


def write_members(gc, group_id: str, member_ids: list[str], fresh: bool,
                  sleep, log) -> dict:
    """Add *member_ids* to the group, skipping ones already in it.

    Members go in PATCH batches of 20. Learn says a bad reference fails the
    whole batch, so a failed batch is retried member by member. A group
    created moments ago can return 400 "...don't exist" while it
    replicates; those calls are retried with a short backoff.
    """
    current: set[str] = set()
    for attempt in range(4):
        try:
            current = gc.list_group_member_ids(group_id)
            break
        except GraphRequestError as e:
            if fresh and e.status_code in (400, 404) and attempt < 3:
                sleep(2 ** (attempt + 1))
                continue
            raise
    to_add = [m for m in dict.fromkeys(member_ids) if m not in current]
    added, failed = 0, {}
    for i in range(0, len(to_add), MAX_MEMBERS_PER_PATCH):
        chunk = to_add[i:i + MAX_MEMBERS_PER_PATCH]
        for attempt in range(4):
            try:
                gc.add_group_members(group_id, chunk)
                added += len(chunk)
                break
            except GraphRequestError as e:
                if fresh and e.status_code == 400 and attempt < 3 and \
                        "exist" in (e.graph_message or "").lower():
                    sleep(2 ** (attempt + 1))
                    continue
                log(f"  batch of {len(chunk)} failed ({e}); adding one by one")
                for mid in chunk:
                    try:
                        gc.add_group_member(group_id, mid)
                        added += 1
                    except GraphRequestError as e2:
                        failed[mid] = str(e2)[:200]
                break
    return {"alreadyMembers": len(member_ids) - len(to_add), "added": added,
            "failed": failed}


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Plan (or apply) mirroring Okta groups into Entra. "
                    "Untranslatable rules are listed for a person to "
                    "rewrite, never dropped.")
    p.add_argument("--inventory", default=FIXTURE_INV)
    p.add_argument("-o", "--output", help="write plan JSON to this path")
    p.add_argument("--live", action="store_true",
                   help="use Microsoft Graph "
                        "(GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET)")
    p.add_argument("--apply", action="store_true",
                   help="create missing groups and write static members "
                        "(requires --live and --expect-tenant)")
    p.add_argument("--expect-tenant", metavar="GUID",
                   help="the Entra tenant id this run is meant for; the run "
                        "stops if the credentials point anywhere else")
    p.add_argument("--owner-id", metavar="OBJECT_ID",
                   help="Entra object id of the user or service principal "
                        "that will own every created group")
    p.add_argument("--allow-no-owner", action="store_true",
                   help="create groups without an owner. With only "
                        "Group.Create, Learn warns such groups can't be "
                        "modified afterwards.")
    p.add_argument("--paused-rules", action="store_true",
                   help="create dynamic groups with rule processing Paused, "
                        "for a dry look before membership is computed")
    p.add_argument("--skip-members", action="store_true",
                   help="create groups only; don't write static members")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive APPLY confirmation")
    p.add_argument("--audit-log", default="toolkit.audit.jsonl",
                   help="append-only audit trail of every write "
                        "(default: %(default)s)")
    p.add_argument("--journal", default="mirror-groups.journal.jsonl",
                   help="checkpoint journal for --apply, tied to the tenant "
                        "(default: %(default)s)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None, graph_client=None, sleep=time.sleep) -> int:
    args = parse_args(argv)
    log = (lambda m: None) if args.quiet else print
    inv = load_inventory(args.inventory)
    plan = plan_groups(inv, "Paused" if args.paused_rules else "On")

    log(f"{len(plan['groups'])} groups planned: " + ", ".join(
        f"{n} {k}" for k, n in sorted(plan["summary"].items())))
    for e in plan["groups"]:
        if e["mode"] == "skip" or (e["rules"] and e["mode"] == "static"):
            log(f"  {e['mode']:7} {e['name']}: {e['reason']}")
    for note in plan["notes"]:
        log(f"note: {note}")

    if args.apply:
        if not args.live:
            print("error: --apply requires --live", file=sys.stderr)
            return 2
        if not args.expect_tenant:
            print("error: --apply requires --expect-tenant <tenant-guid>",
                  file=sys.stderr)
            return 2
        if not args.owner_id and not args.allow_no_owner:
            print("error: --apply needs --owner-id (or --allow-no-owner); "
                  "groups created by an app without an owner may not be "
                  "manageable afterwards", file=sys.stderr)
            return 2
        gc = graph_client or GraphClient()
        org = check_graph_tenant(gc, log, args.expect_tenant)
        if org is None:
            return 2
        try:
            journal = Journal(args.journal, binding={
                "script": "mirror_groups",
                "entraTenantId": (org.get("id") or "").lower(),
                "oktaSource": inv["source"].get("oktaOrgId")
                or inv["source"].get("oktaDomain")
                or inv["source"].get("rawFile") or "unknown"})
        except JournalMismatchError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        todo = [e for e in plan["groups"] if e["mode"] != "skip"]
        summary = (
            f"About to create up to {len(todo)} group(s) and write static "
            f"members in Entra tenant {org.get('displayName') or '?'} "
            f"({org.get('id') or '?'}).\n"
            f"Journal: {args.journal}  |  Audit log: {args.audit_log}\n"
            f"Name collisions are flagged, never auto-created.")
        if not confirm_apply(summary, args.yes):
            print("aborted -- nothing was created", file=sys.stderr)
            return 1
        audit = AuditLog(args.audit_log, script="mirror_groups",
                         tenant=org.get("id", ""))
        audit.record("apply-start", detail={"candidates": len(todo),
                                            "journal": args.journal})
        stamped: dict[str, dict] = {}
        by_name: dict[str, list] = {}
        for eg in gc.list_groups():
            sid = extract_stamped_id(eg.get("description"))
            if sid:
                stamped[sid] = eg
            by_name.setdefault((eg.get("displayName") or "").lower(),
                               []).append(eg)
        upn_index = _index_entra_users(gc.list_users()) \
            if not args.skip_members else {}
        collisions, results = [], []
        n_created = n_failed = n_resumed = 0
        for entry in todo:
            key = entry["oktaGroupId"]
            res = {"oktaGroupId": key, "name": entry["name"]}
            results.append(res)
            entra_id, fresh = None, False
            prior = journal.get(key)
            if journal.completed(key):
                n_resumed += 1
                entra_id = ((prior or {}).get("detail") or {}).get("entraId")
                log(f"resume-skip (group already done): {entry['name']}")
            else:
                try:
                    hit = stamped.get(key)
                    dupes = by_name.get(entry["name"].lower(), [])
                    if hit is not None:
                        entra_id = hit.get("id")
                        journal.record(key, "skipped", {"entraId": entra_id})
                        log(f"skip (already mirrored): {entry['name']}")
                    elif dupes:
                        collisions.append({
                            "oktaGroupId": key, "name": entry["name"],
                            "entraMatches": [
                                {"id": d.get("id"),
                                 "displayName": d.get("displayName"),
                                 "description": d.get("description")}
                                for d in dupes]})
                        log(f"COLLISION: Entra already has {len(dupes)} "
                            f"group(s) named {entry['name']!r} with no Okta "
                            f"stamp -- flagged, not created")
                        res["collision"] = True
                        continue
                    else:
                        body = dict(entry["entraGroup"])
                        if args.owner_id:
                            body["owners@odata.bind"] = [
                                "https://graph.microsoft.com/v1.0/"
                                f"directoryObjects/{args.owner_id}"]
                        created = gc.create_group(body)
                        entra_id, fresh = created["id"], True
                        journal.record(key, "ok", {"entraId": entra_id})
                        audit.record("create-group", "group", entra_id,
                                     entry["name"], {"oktaId": key,
                                                     "mode": entry["mode"]})
                        n_created += 1
                        log(f"created {entry['name']} -> {entra_id} "
                            f"({entry['mode']})")
                except Exception as e:  # noqa: BLE001 - keep the batch going
                    journal.record(key, "error", str(e)[:300])
                    audit.record("create-group-failed", "group", "",
                                 entry["name"], {"oktaId": key,
                                                 "error": str(e)[:200]})
                    n_failed += 1
                    res["error"] = str(e)[:300]
                    log(f"ERROR creating {entry['name']}: {e} -- continuing")
                    continue
            res["entraId"] = entra_id

            mkey = f"members:{key}"
            if args.skip_members or entry["mode"] != "static" or \
                    not entry["members"] or journal.completed(mkey):
                continue
            if not entra_id:
                res["membersError"] = "Entra group id unknown; rerun"
                continue
            resolved, unresolved = [], []
            for login in entry["members"]:
                hits = upn_index.get(login.lower(), [])
                if len(hits) == 1:
                    resolved.append(hits[0]["id"])
                else:
                    unresolved.append(
                        f"{login}: {'not in Entra' if not hits else 'ambiguous'}")
            try:
                out = write_members(gc, entra_id, resolved, fresh, sleep, log)
            except Exception as e:  # noqa: BLE001 - keep the batch going
                journal.record(mkey, "error", str(e)[:300])
                res["membersError"] = str(e)[:300]
                log(f"ERROR writing members of {entry['name']}: {e}")
                continue
            out["unresolved"] = unresolved
            res["members"] = out
            status = "ok" if not out["failed"] and not unresolved else "error"
            journal.record(mkey, status, {
                "added": out["added"], "failed": len(out["failed"]),
                "unresolved": len(unresolved)})
            audit.record("add-group-members", "group", entra_id,
                         entry["name"], {"oktaId": key, "added": out["added"],
                                         "failed": len(out["failed"]),
                                         "unresolved": len(unresolved)})
            log(f"members {entry['name']}: +{out['added']}, "
                f"{out['alreadyMembers']} already there, "
                f"{len(out['failed'])} failed, {len(unresolved)} unresolved")
        if collisions:
            log(f"\nNAME COLLISIONS NEEDING REVIEW ({len(collisions)}):")
            for c in collisions:
                ids = ", ".join(m["id"] for m in c["entraMatches"])
                log(f"  - {c['name']} (okta {c['oktaGroupId']}): "
                    f"Entra group(s) {ids}")
        log(f"apply done: {n_created} created, {n_failed} failed, "
            f"{n_resumed} resumed-skipped, {len(collisions)} collisions "
            f"(journal: {args.journal})")
        audit.record("apply-done", detail={
            "created": n_created, "failed": n_failed,
            "resumed": n_resumed, "collisions": len(collisions)})
        plan["applyResults"] = results
        plan["collisions"] = collisions

    if args.output:
        write_json(args.output, plan)  # scrubbed + 0600 + atomic
        log(f"plan written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
