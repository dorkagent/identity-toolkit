"""Live export against a mocked Okta org: endpoints, paging, checkpoints."""

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import _paths  # noqa: F401
import export_inventory as ex
from fakes import FakeOkta
from okta_api import OktaAuthError, OktaClient, OrgMismatchError


def org_data():
    users = [{"id": f"00u{i}", "status": "ACTIVE",
              "profile": {"login": f"u{i}@example.com",
                          "email": f"u{i}@example.com",
                          "department": "Eng" if i < 2 else "Ops"},
              "credentials": {"provider": {"type": "OKTA"}}}
             for i in range(3)]
    return {
        "org": {"id": "00oACME", "subdomain": "acme"},
        "/api/v1/users": users,
        "deprovisioned": [{"id": "00u9", "status": "DEPROVISIONED",
                           "profile": {"login": "gone@example.com"},
                           "credentials": {"provider": {"type": "OKTA"}}}],
        "/api/v1/groups": [
            {"id": "00gENG", "type": "OKTA_GROUP",
             "profile": {"name": "Engineering", "description": ""}},
            {"id": "00gALL", "type": "BUILT_IN",
             "profile": {"name": "Everyone"}}],
        "/api/v1/groups/rules": [
            {"id": "0prR1", "name": "eng", "status": "ACTIVE", "type": "group_rule",
             "conditions": {"expression": {"value": 'user.department == "Eng"',
                                           "type": "urn:okta:expression:1.0"},
                            "people": {"users": {"exclude": []}}},
             "actions": {"assignUserToGroups": {"groupIds": ["00gENG"]}}}],
        "/api/v1/groups/00gENG/users": [{"id": "00u0"}, {"id": "00u1"}],
        "/api/v1/groups/00gALL/users": [{"id": f"00u{i}"} for i in range(3)],
        "/api/v1/apps": [
            {"id": "0oaS", "name": "slack", "label": "Slack",
             "signOnMode": "SAML_2_0", "status": "ACTIVE",
             "settings": {"signOn": {"audience": "https://slack.com",
                                     "ssoAcsUrl": "https://slack.com/sso/saml",
                                     "idpIssuer": "http://www.okta.com/exk1"}}}],
        "/api/v1/apps/0oaS/users": [{"id": "00u0", "scope": "USER"},
                                    {"id": "00u1", "scope": "GROUP"}],
        "/api/v1/apps/0oaS/groups": [{"id": "00gENG"}],
        "policies": {
            "ACCESS_POLICY": [{"id": "rst1", "name": "app policy",
                               "type": "ACCESS_POLICY", "status": "ACTIVE"}],
            "OKTA_SIGN_ON": [{"id": "00p1", "name": "Default",
                              "type": "OKTA_SIGN_ON", "status": "ACTIVE"}],
        },
        "/api/v1/policies/rst1/rules": [{"id": "rul1", "name": "r"}],
        "/api/v1/policies/00p1/rules": [],
        "/api/v1/api-tokens": [{"id": "00T1", "name": "ci", "userId": "00u0"}],
    }


def client_for(fake, **kw):
    return OktaClient(fake.BASE, "token", session=fake.session,
                      sleep=lambda s: None, **kw)


class OktaClientTest(unittest.TestCase):
    def test_api_tokens_uses_real_path(self):
        fake = FakeOkta(org_data())
        tokens = list(client_for(fake).list_api_tokens())
        self.assertEqual(tokens[0]["id"], "00T1")
        self.assertIn("/api/v1/api-tokens", fake.hits)
        self.assertNotIn("/api/v1/api/tokens", fake.hits)

    def test_users_include_deprovisioned_and_follow_paging(self):
        fake = FakeOkta(org_data(), page_size=2)
        users = list(client_for(fake).list_users())
        self.assertEqual([u["id"] for u in users],
                         ["00u0", "00u1", "00u2", "00u9"])
        searches = [c for c in fake.session.calls if "search" in c[2]]
        self.assertEqual(searches[0][2]["search"], 'status eq "DEPROVISIONED"')

    def test_verify_org_accepts_other_okta_cells(self):
        data = org_data()
        fake = FakeOkta(data)
        c = OktaClient("https://acme.oktapreview.com", "t",
                       session=fake.session)
        self.assertEqual(c.verify_org()["id"], "00oACME")

    def test_custom_domain_needs_expected_org_id(self):
        fake = FakeOkta(org_data())
        c = OktaClient("https://login.acme.com", "t", session=fake.session)
        with self.assertRaises(OrgMismatchError):
            c.verify_org()
        c = OktaClient("https://login.acme.com", "t", session=fake.session,
                       expect_org_id="00oACME")
        self.assertEqual(c.verify_org()["subdomain"], "acme")
        c = OktaClient("https://login.acme.com", "t", session=fake.session,
                       expect_org_id="00oOTHER")
        with self.assertRaises(OrgMismatchError):
            c.verify_org()


class LiveExportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "inv.json")

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, fake, *extra):
        err, out = StringIO(), StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            rc = ex.main(["--live", "-o", self.out, *extra],
                         client=client_for(fake))
        return rc, err.getvalue()

    def test_policy_types_are_the_valid_enum(self):
        self.assertIn("ACCESS_POLICY", ex.POLICY_TYPES)
        self.assertNotIn("OAUTH_AUTHORIZATION_POLICY", ex.POLICY_TYPES)
        self.assertEqual(len(ex.POLICY_TYPES), 12)

    def test_full_export_shape(self):
        fake = FakeOkta(org_data(), errors={
            "/api/v1/policies?type=ENTITY_RISK": 400})
        rc, _ = self.run_main(fake)
        self.assertEqual(rc, 0)
        inv = json.load(open(self.out))
        self.assertEqual(len(inv["users"]), 4)          # incl. DEPROVISIONED
        self.assertEqual(inv["exportErrors"], {})
        self.assertEqual(inv["source"]["policyTypesUnavailable"], ["ENTITY_RISK"])
        self.assertEqual({p["type"] for p in inv["policies"]},
                         {"ACCESS_POLICY", "OKTA_SIGN_ON"})
        eng = next(g for g in inv["groups"] if g["id"] == "00gENG")
        self.assertEqual(eng["ruleIds"], ["0prR1"])
        self.assertEqual(eng["dynamicRule"], 'user.department == "Eng"')
        self.assertEqual(inv["groupRules"][0]["targetGroupIds"], ["00gENG"])
        app = inv["apps"][0]
        self.assertEqual(app["sso"]["ssoAcsUrl"], "https://slack.com/sso/saml")
        self.assertEqual(app["sso"]["idpIssuer"], "http://www.okta.com/exk1")
        self.assertEqual(app["assignedUsersDirect"], ["00u0"])
        self.assertEqual(inv["apiTokens"][0]["id"], "00T1")
        self.assertEqual(inv["source"]["oktaOrgId"], "00oACME")

    def test_forbidden_section_is_recorded_not_fatal(self):
        fake = FakeOkta(org_data(), errors={"/api/v1/api-tokens": 403})
        rc, err = self.run_main(fake)
        self.assertEqual(rc, 1)
        inv = json.load(open(self.out))
        self.assertIn("apiTokens", inv["exportErrors"])
        self.assertEqual(len(inv["users"]), 4)
        self.assertIn("apiTokens", err)

    def test_checkpoint_survives_revoked_token_and_resumes(self):
        fake = FakeOkta(org_data())
        fake.fail_after["/api/v1/apps/0oaS/groups"] = 0   # 401 on first call
        rc, err = self.run_main(fake)
        self.assertEqual(rc, 2)
        self.assertIn("--resume", err)
        parts = self.out + ".parts"
        self.assertTrue(os.path.exists(os.path.join(parts, "users.json")))
        mode = stat.S_IMODE(os.stat(os.path.join(parts, "users.json")).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertFalse(os.path.exists(self.out))

        fake2 = FakeOkta(org_data())
        rc, _ = self.run_main(fake2, "--resume")
        self.assertEqual(rc, 0)
        self.assertNotIn("/api/v1/users", fake2.hits)     # came from checkpoint
        self.assertIn("/api/v1/apps/0oaS/groups", fake2.hits)
        self.assertEqual(len(json.load(open(self.out))["users"]), 4)

    def test_auth_error_carries_status(self):
        fake = FakeOkta(org_data(), errors={"/api/v1/apps": 403})
        with self.assertRaises(OktaAuthError) as cm:
            list(client_for(fake).list_apps())
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
