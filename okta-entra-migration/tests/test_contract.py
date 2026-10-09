"""Contract tests: inventory schema + fixture files.

These pin the inventory contract that every downstream script relies on.
If the contract changes, these tests fail first -- update them and every
consumer deliberately, not by accident.
"""

import json
import os
import tempfile
import unittest

import _paths  # noqa: F401
from _paths import FIXTURES
from inventory import new_inventory, save_inventory, load_inventory
from export_inventory import raw_to_contract, contract_user

USER_REQUIRED = {"id", "login", "email", "firstName", "lastName", "status",
                 "userType", "credentialProvider", "department", "title",
                 "manager", "groups", "apps", "profile"}
GROUP_REQUIRED = {"id", "name", "description", "type", "members",
                  "assignedApps", "dynamicRule", "dynamicRuleStatus"}
APP_REQUIRED = {"id", "name", "label", "signOnMode", "status"}


class FixtureFilesTest(unittest.TestCase):
    def test_raw_fixture_parses(self):
        raw = json.load(open(os.path.join(FIXTURES, "okta-raw.sample.json")))
        self.assertIn("users", raw)
        self.assertGreater(len(raw["users"]), 0)

    def test_entra_fixture_parses(self):
        entra = json.load(
            open(os.path.join(FIXTURES, "entra-tenant.sample.json")))
        self.assertIn("users", entra)

    def test_raw_users_have_credentials_shape(self):
        raw = json.load(open(os.path.join(FIXTURES, "okta-raw.sample.json")))
        for u in raw["users"]:
            provider = (u.get("credentials") or {}).get("provider") or {}
            self.assertIn("type", provider,
                          f"user {u.get('id')} missing credentials.provider.type")

    def test_fixture_covers_ad_mastered_user(self):
        # The AD-mastered guard is only meaningful if a fixture
        # exercises it.
        raw = json.load(open(os.path.join(FIXTURES, "okta-raw.sample.json")))
        types = {(u.get("credentials") or {}).get("provider", {}).get("type")
                 for u in raw["users"]}
        self.assertIn("ACTIVE_DIRECTORY", types)


class ContractShapeTest(unittest.TestCase):
    def setUp(self):
        raw = json.load(open(os.path.join(FIXTURES, "okta-raw.sample.json")))
        self.inv = raw_to_contract(raw, {"live": False, "rawFile": "test"})

    def test_user_contract_keys(self):
        for u in self.inv["users"]:
            self.assertTrue(USER_REQUIRED <= set(u.keys()),
                            f"user {u.get('id')} missing keys: "
                            f"{USER_REQUIRED - set(u.keys())}")

    def test_group_contract_keys(self):
        for g in self.inv["groups"]:
            self.assertTrue(GROUP_REQUIRED <= set(g.keys()),
                            f"group {g.get('id')} missing keys")

    def test_app_contract_keys(self):
        for a in self.inv["apps"]:
            self.assertTrue(APP_REQUIRED <= set(a.keys()),
                            f"app {a.get('id')} missing keys")

    def test_credential_provider_flows_through(self):
        by_login = {u["login"]: u for u in self.inv["users"]}
        self.assertEqual(
            by_login["alan.turing@example.com"]["credentialProvider"],
            "ACTIVE_DIRECTORY")
        self.assertEqual(
            by_login["ada.lovelace@example.com"]["credentialProvider"],
            "OKTA")

    def test_missing_credentials_defaults_none(self):
        u = contract_user(
            {"id": "x", "status": "ACTIVE",
             "profile": {"login": "x@y.z"}}, [], [])
        self.assertIsNone(u["credentialProvider"])

    def test_save_load_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "inv.json")
            save_inventory(self.inv, p)
            back = load_inventory(p)
        self.assertEqual(len(back["users"]), len(self.inv["users"]))
        self.assertEqual(back["users"][0]["login"],
                         self.inv["users"][0]["login"])

    def test_new_inventory_sections(self):
        inv = new_inventory()
        for section in ("users", "groups", "apps", "policies",
                        "apiTokens", "oauthApps"):
            self.assertIn(section, inv)


if __name__ == "__main__":
    unittest.main()
