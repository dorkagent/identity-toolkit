"""mirror_groups: plan classification and the --apply loop against mocked Graph."""

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import _paths  # noqa: F401
import mirror_groups as mg
from entra_names import upn_problem
from fakes import FakeGraph
from inventory import save_inventory

TENANT = FakeGraph.TENANT
OWNER = "99999999-0000-0000-0000-000000000001"


def user(i, **profile):
    login = f"u{i}@example.com"
    p = {"login": login, "email": login, **profile}
    return {"id": f"00u{i}", "login": login, "email": login,
            "status": "ACTIVE", "profile": p}


def inventory(n_static_members=3):
    users = [user(i, department="Eng" if i < 2 else "Ops")
             for i in range(max(n_static_members, 3))]
    rule = lambda rid, expr, gid, **kw: {  # noqa: E731
        "id": rid, "name": rid, "status": kw.get("status", "ACTIVE"),
        "expression": expr, "targetGroupIds": [gid],
        "excludedUserIds": kw.get("excl", []), "excludedGroupIds": []}
    return {
        "source": {"oktaOrgId": "00oACME"},
        "users": users,
        "groups": [
            {"id": "00gENG", "name": "Engineering", "type": "OKTA_GROUP",
             "members": ["00u0", "00u1"]},
            {"id": "00gMIX", "name": "Eng plus one", "type": "OKTA_GROUP",
             "members": ["00u0", "00u1", "00u2"]},
            {"id": "00gFIN", "name": "Finance (EMEA)", "type": "OKTA_GROUP",
             "members": ["00u2"]},
            {"id": "00gSTAT", "name": "Static Team", "type": "OKTA_GROUP",
             "members": [u["id"] for u in users[:n_static_members]]},
            {"id": "00gALL", "name": "Everyone", "type": "BUILT_IN",
             "members": ["00u0"]},
            {"id": "00gAD", "name": "AD Admins", "type": "APP_GROUP",
             "members": []},
        ],
        "groupRules": [
            rule("r1", 'user.department == "Eng"', "00gENG"),
            rule("r2", 'user.department == "Eng"', "00gMIX"),
            rule("r3", 'user.costCenter == "FIN"', "00gFIN"),
            rule("r4", 'user.department == "Ops"', "00gSTAT", status="INACTIVE"),
        ],
        "apps": [], "policies": [], "apiTokens": [], "oauthApps": [],
    }


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.plan = mg.plan_groups(inventory())
        self.by = {e["oktaGroupId"]: e for e in self.plan["groups"]}

    def test_rule_only_group_becomes_dynamic(self):
        e = self.by["00gENG"]
        self.assertEqual(e["mode"], "dynamic")
        g = e["entraGroup"]
        self.assertEqual(g["groupTypes"], ["DynamicMembership"])
        self.assertEqual(g["membershipRule"], '(user.department -eq "Eng")')
        self.assertEqual(g["membershipRuleProcessingState"], "On")
        self.assertEqual(e["members"], [])

    def test_direct_members_force_static_with_manual_item(self):
        e = self.by["00gMIX"]
        self.assertEqual(e["mode"], "static")
        self.assertIn("aren't explained by the rules", e["reason"])
        self.assertEqual(len(e["members"]), 3)
        self.assertTrue(any(m["oktaGroupId"] == "00gMIX"
                            for m in self.plan["manualItems"]))

    def test_untranslatable_rule_is_static_snapshot_not_empty(self):
        e = self.by["00gFIN"]
        self.assertEqual(e["mode"], "static")
        self.assertEqual(e["members"], ["u2@example.com"])
        self.assertTrue(any(u["ruleId"] == "r3"
                            for u in self.plan["untranslatedRules"]))

    def test_inactive_rule_is_ignored(self):
        e = self.by["00gSTAT"]
        self.assertEqual(e["mode"], "static")
        self.assertEqual(e["rules"][0]["ignored"], "rule is not ACTIVE")

    def test_builtin_and_app_groups_are_skipped(self):
        self.assertEqual(self.by["00gALL"]["mode"], "skip")
        self.assertEqual(self.by["00gAD"]["mode"], "skip")
        self.assertIsNone(self.by["00gALL"]["entraGroup"])

    def test_every_payload_has_valid_unique_mail_nickname(self):
        nicks = [e["entraGroup"]["mailNickname"] for e in self.plan["groups"]
                 if e["entraGroup"]]
        self.assertEqual(len(nicks), len(set(nicks)))
        for n in nicks:
            self.assertLessEqual(len(n), 64)
            self.assertIsNone(upn_problem(n + "@x.com"), n)
        self.assertNotIn(" ", self.by["00gFIN"]["entraGroup"]["mailNickname"])
        self.assertNotIn("(", self.by["00gFIN"]["entraGroup"]["mailNickname"])

    def test_licence_note(self):
        self.assertTrue(any("P1" in n for n in self.plan["notes"]))

    def test_old_single_rule_contract_still_works(self):
        inv = {"users": [user(0, department="Eng")],
               "groups": [{"id": "00gX", "name": "X", "members": ["00u0"],
                           "dynamicRule": 'user.department == "Eng"',
                           "dynamicRuleStatus": "ACTIVE"}]}
        e = mg.plan_groups(inv)["groups"][0]
        self.assertEqual(e["mode"], "dynamic")


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inv = os.path.join(self.tmp.name, "inv.json")
        self.journal = os.path.join(self.tmp.name, "j.jsonl")
        self.audit = os.path.join(self.tmp.name, "a.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def graph_with_users(self, n):
        return FakeGraph(users=[{"id": f"e-{i}",
                                 "userPrincipalName": f"u{i}@example.com"}
                                for i in range(n)], page_size=7)

    def apply(self, fake, inv=None, *extra, expect=TENANT, owner=OWNER):
        save_inventory(inv or inventory(), self.inv)
        argv = ["--inventory", self.inv, "--live", "--apply", "--yes",
                "--journal", self.journal, "--audit-log", self.audit, *extra]
        if expect:
            argv += ["--expect-tenant", expect]
        if owner:
            argv += ["--owner-id", owner]
        err, out = StringIO(), StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            rc = mg.main(argv, graph_client=fake.client(), sleep=lambda s: None)
        return rc, out.getvalue(), err.getvalue()

    def test_apply_needs_expected_tenant_and_owner(self):
        fake = self.graph_with_users(3)
        self.assertEqual(self.apply(fake, None, expect=None)[0], 2)
        self.assertEqual(self.apply(fake, None, owner=None)[0], 2)
        self.assertEqual(fake.created_groups, [])

    def test_wrong_tenant_stops_before_any_write(self):
        fake = self.graph_with_users(3)
        rc, _, err = self.apply(fake, None,
                              expect="00000000-0000-0000-0000-000000000000")
        self.assertEqual(rc, 2)
        self.assertIn("not the expected tenant", err)
        self.assertEqual(fake.created_groups, [])

    def test_creates_groups_with_required_fields_and_owner(self):
        fake = self.graph_with_users(3)
        rc, out, _ = self.apply(fake)
        self.assertEqual(rc, 0, out)
        names = sorted(g["displayName"] for g in fake.created_groups)
        self.assertEqual(names, ["Eng plus one", "Engineering",
                                 "Finance (EMEA)", "Static Team"])
        for g in fake.created_groups:
            self.assertTrue(g["mailNickname"])
            self.assertEqual(g["owners@odata.bind"],
                             [f"https://graph.microsoft.com/v1.0/"
                              f"directoryObjects/{OWNER}"])
        dyn = next(g for g in fake.created_groups
                   if g["displayName"] == "Engineering")
        self.assertEqual(dyn["membershipRuleProcessingState"], "On")

    def test_members_written_in_batches_of_20_and_diffed(self):
        fake = self.graph_with_users(45)
        inv = inventory(n_static_members=45)
        rc, out, _ = self.apply(fake, inv)
        self.assertEqual(rc, 0, out)
        static = next(g for g in fake.groups if g["displayName"] == "Static Team")
        sizes = [len(refs) for gid, refs in fake.patches if gid == static["id"]]
        self.assertEqual(sizes, [20, 20, 5])
        self.assertEqual(len(fake.members[static["id"]]), 45)
        # Dynamic groups never get members written.
        eng = next(g for g in fake.groups if g["displayName"] == "Engineering")
        self.assertNotIn(eng["id"], [gid for gid, _ in fake.patches])

    def test_rerun_resumes_and_skips_existing_members(self):
        fake = self.graph_with_users(5)
        inv = inventory(n_static_members=5)
        self.apply(fake, inv)
        created, patches = len(fake.created_groups), len(fake.patches)
        # Wipe the members journal entries' effect by using a new journal:
        # the stamped groups are found, members already present are skipped.
        os.remove(self.journal)
        rc, out, _ = self.apply(fake, inv)
        self.assertEqual(rc, 0)
        self.assertEqual(len(fake.created_groups), created)
        self.assertEqual(len(fake.patches), patches)
        self.assertIn("already mirrored", out)

    def test_failed_batch_falls_back_to_single_adds(self):
        fake = self.graph_with_users(3)
        fake.reject_batches = True
        rc, out, _ = self.apply(fake)
        self.assertEqual(rc, 0)
        self.assertTrue(fake.ref_posts)
        self.assertIn("one by one", out)

    def test_unresolved_members_are_reported(self):
        fake = self.graph_with_users(1)   # only u0 exists in Entra
        rc, out, _ = self.apply(fake, None, "-o",
                              os.path.join(self.tmp.name, "plan.json"))
        plan = json.load(open(os.path.join(self.tmp.name, "plan.json")))
        fin = next(r for r in plan["applyResults"] if r["oktaGroupId"] == "00gFIN")
        self.assertEqual(fin["members"]["unresolved"],
                         ["u2@example.com: not in Entra"])

    def test_name_collision_is_flagged_not_created(self):
        fake = self.graph_with_users(3)
        fake.groups.append({"id": "pre", "displayName": "Static Team",
                            "description": "made by hand"})
        rc, out, _ = self.apply(fake)
        self.assertIn("COLLISION", out)
        self.assertNotIn("Static Team",
                         [g["displayName"] for g in fake.created_groups])

    def test_journal_from_other_tenant_is_refused(self):
        fake = self.graph_with_users(3)
        self.apply(fake)
        other = FakeGraph(tenant_id="22222222-2222-2222-2222-222222222222")
        rc, _, err = self.apply(other, None,
                              expect="22222222-2222-2222-2222-222222222222")
        self.assertEqual(rc, 2)
        self.assertIn("different run context", err)
        self.assertEqual(other.created_groups, [])


if __name__ == "__main__":
    unittest.main()
