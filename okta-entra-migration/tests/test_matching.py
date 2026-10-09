"""Unit tests: user matching tiers + identity-safety guards."""

import unittest

import _paths  # noqa: F401
import import_users as iu


def okta_user(login, **kw):
    u = {"id": "00u" + login, "login": login,
         "email": kw.pop("email", login), "status": "ACTIVE",
         "userType": "USER", "credentialProvider": "OKTA",
         "firstName": "T", "lastName": "U"}
    u.update(kw)
    return u


class MatchTiersTest(unittest.TestCase):
    def test_tier1_upn_match(self):
        b = iu.match_users(
            [okta_user("ada@example.com")],
            [{"userPrincipalName": "ada@example.com", "mail": "ada@example.com"}])
        self.assertEqual(len(b["matched"]), 1)
        self.assertEqual(b["to_create"], [])

    def test_tier2_email_match_flags_rename(self):
        b = iu.match_users(
            [okta_user("ada.new@example.com",
                       email="ada@example.com")],
            [{"userPrincipalName": "ada@example.com",
              "mail": "ada@example.com"}])
        self.assertEqual(b["to_create"], [])
        self.assertEqual(len(b["flagged"]), 1)
        self.assertIn("possible UPN rename", b["flagged"][0]["reason"])

    def test_no_match_goes_to_create(self):
        b = iu.match_users([okta_user("new@example.com")], [])
        self.assertEqual(len(b["to_create"]), 1)

    def test_deprovisioned_flagged(self):
        b = iu.match_users(
            [okta_user("old@example.com", status="DEPROVISIONED")], [])
        self.assertEqual(b["to_create"], [])
        self.assertIn("deprovisioned", b["flagged"][0]["reason"])

    def test_service_account_flagged(self):
        b = iu.match_users(
            [okta_user("svc-backup@example.com", userType="SERVICE")], [])
        self.assertEqual(b["to_create"], [])
        self.assertIn("service account", b["flagged"][0]["reason"])

    def test_ad_mastered_never_created(self):
        b = iu.match_users(
            [okta_user("ad.user@example.com",
                       credentialProvider="ACTIVE_DIRECTORY")], [])
        self.assertEqual(b["to_create"], [])
        self.assertIn("ACTIVE_DIRECTORY", b["flagged"][0]["reason"])
        self.assertIn("Entra Connect", b["flagged"][0]["reason"])

    def test_ldap_mastered_never_created(self):
        b = iu.match_users(
            [okta_user("ldap.user@example.com",
                       credentialProvider="ldap")], [])
        self.assertEqual(b["to_create"], [])

    def test_unknown_provider_proceeds(self):
        b = iu.match_users(
            [okta_user("x@example.com", credentialProvider=None)], [])
        self.assertEqual(len(b["to_create"]), 1)

    def test_missing_login_flagged(self):
        b = iu.match_users([okta_user("", email="")], [])
        self.assertIn("no login", b["flagged"][0]["reason"])

    def test_mutation_policy_is_create_only(self):
        self.assertEqual(iu.MUTATION_POLICY["mode"], "create-only")
        self.assertTrue(iu.MUTATION_POLICY["neverDeletes"])


if __name__ == "__main__":
    unittest.main()
