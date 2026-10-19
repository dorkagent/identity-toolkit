"""Pin the AI-agent identity risk rubric against the bundled fixture.

Stdlib only, no network. Run from the ai-agent-identity directory:

    python3 -m unittest discover -s tests
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import inventory_agent_identities as mod  # noqa: E402

HERE = os.path.dirname(__file__)
FIXTURE = os.path.join(HERE, "..", "fixtures", "agent-inventory.sample.json")
NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


class TestRubricTiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = load_fixture()
        cls.users = {u["id"]: u for u in cls.inv["users"]}
        cls.admin_ids = mod.admin_group_ids(cls.inv["groups"])
        cls.tokens = {t["id"]: t for t in cls.inv["apiTokens"]}
        cls.apps = {a["id"]: a for a in cls.inv["oauthApps"]}

    def test_critical_token_never_expires_with_admin_owner(self):
        f = mod.assess_token(self.tokens["00T-crit1"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "critical")
        self.assertTrue(any("admin" in r for r in f["reasons"]))
        self.assertTrue(any("never expires" in r for r in f["reasons"]))

    def test_high_token_never_expires(self):
        f = mod.assess_token(self.tokens["00T-high1"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "high")
        self.assertTrue(any("never expires" in r for r in f["reasons"]))

    def test_high_token_orphaned_owner(self):
        f = mod.assess_token(self.tokens["00T-high2"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "high")
        self.assertTrue(any("orphaned" in r for r in f["reasons"]))

    def test_medium_token_old(self):
        f = mod.assess_token(self.tokens["00T-med1"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "medium")
        self.assertTrue(any("365" in r for r in f["reasons"]))

    def test_low_token_healthy(self):
        f = mod.assess_token(self.tokens["00T-low1"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "low")
        self.assertEqual(f["reasons"], [])

    def test_high_oauth_broad_scopes(self):
        f = mod.assess_oauth_app(self.apps["0oa-ai1"])
        self.assertEqual(f["tier"], "high")
        self.assertTrue(any("broad scopes" in r for r in f["reasons"]))

    def test_medium_oauth_narrow_scopes(self):
        f = mod.assess_oauth_app(self.apps["0oa-met1"])
        self.assertEqual(f["tier"], "medium")

    def test_low_oauth_user_delegated(self):
        f = mod.assess_oauth_app(self.apps["0oa-dash1"])
        self.assertEqual(f["tier"], "low")

    def test_medium_service_user_human_groups(self):
        groups = {g["id"]: g for g in self.inv["groups"]}
        user = self.users["00u-svc-ai"]
        f = mod.assess_service_user(user, groups, self.admin_ids)
        self.assertEqual(f["tier"], "medium")
        self.assertTrue(any("human-like" in r for r in f["reasons"]))

    def test_low_service_user_clean(self):
        groups = {g["id"]: g for g in self.inv["groups"]}
        user = self.users["00u-svc-etl"]
        f = mod.assess_service_user(user, groups, self.admin_ids)
        self.assertEqual(f["tier"], "low")

    def test_highest_rule_wins(self):
        # Never-expires (high) plus admin owner (critical) lands critical,
        # and both reasons are kept for auditability.
        f = mod.assess_token(self.tokens["00T-crit1"], self.users,
                             self.admin_ids, NOW)
        self.assertEqual(f["tier"], "critical")
        self.assertGreaterEqual(len(f["reasons"]), 2)

    def test_coverage_clean_on_fixture(self):
        self.assertEqual(mod.coverage_check(self.inv), [])

    def test_end_to_end_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.md")
            rc = mod.main(["--inventory", FIXTURE, "-o", out, "-q"])
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                report = fh.read()
        for tier in ("critical", "high", "medium", "low"):
            self.assertIn(f"**{tier}**", report)
        self.assertIn("deploy-bot-token", report)


if __name__ == "__main__":
    unittest.main()
