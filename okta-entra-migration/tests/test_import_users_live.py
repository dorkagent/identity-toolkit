"""import_users: payload rules, guards, and the --apply loop against mocked Graph."""

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

import _paths  # noqa: F401
import import_users as iu
from entra_names import mail_nickname, upn_problem
from fakes import FakeGraph
from inventory import save_inventory

TENANT = FakeGraph.TENANT
GUID = "6F8B3A2C-1D4E-4F5A-8B7C-9D0E1F2A3B4C"


def ou(login, status="ACTIVE", email=None, **profile):
    email = email or login
    p = {"login": login, "email": email, **profile}
    return {"id": "00u" + login.split("@")[0], "login": login, "email": email,
            "firstName": "T", "lastName": "U", "status": status,
            "userType": "USER", "credentialProvider": "OKTA",
            "countryCode": profile.get("countryCode"), "profile": p}


class PayloadTest(unittest.TestCase):
    def test_mail_nickname_is_sanitized(self):
        body = iu.entra_user_payload(ou("o'brien@example.com"))
        self.assertEqual(body["mailNickname"], "o'brien")
        self.assertEqual(mail_nickname("ann+test"), "ann-test")
        self.assertEqual(mail_nickname("José Núñez"), "Jos-N-ez")
        self.assertIsNone(upn_problem(mail_nickname("a+b c@d") + "@x.com"))

    def test_usage_location_from_okta_then_default_then_unset(self):
        self.assertEqual(iu.usage_location_for(ou("a@x.com", countryCode="gb"), "US"), "GB")
        self.assertEqual(iu.usage_location_for(ou("a@x.com"), "US"), "US")
        self.assertIsNone(iu.usage_location_for(ou("a@x.com"), None))
        self.assertIsNone(iu.usage_location_for(ou("a@x.com", countryCode="USA"), None))
        self.assertNotIn("usageLocation", iu.entra_user_payload(ou("a@x.com")))

    def test_profile_attributes_carried_for_dynamic_rules(self):
        body = iu.entra_user_payload(ou("a@x.com", city="Austin",
                                        employeeNumber="E1",
                                        organization="Acme"), "US")
        self.assertEqual((body["city"], body["employeeId"], body["companyName"],
                          body["usageLocation"]), ("Austin", "E1", "Acme", "US"))

    def test_status_mapping(self):
        for status, enabled in (("ACTIVE", True), ("LOCKED_OUT", True),
                                ("PASSWORD_EXPIRED", True), ("RECOVERY", True),
                                ("SUSPENDED", False), ("STAGED", False),
                                ("PROVISIONED", False)):
            with self.subTest(status=status):
                body = iu.entra_user_payload(ou("a@x.com", status=status))
                self.assertIs(body["accountEnabled"], enabled)


class GuardTest(unittest.TestCase):
    def test_plus_in_upn_is_flagged(self):
        b = iu.match_users([ou("ann+test@example.com")], [])
        self.assertEqual(b["to_create"], [])
        self.assertIn("'+'", b["flagged"][0]["reason"])

    def test_okta_side_duplicate_email_flags_both(self):
        b = iu.match_users([ou("a@example.com", email="x@example.com"),
                            ou("b@example.com", email="x@example.com")], [])
        self.assertEqual(len(b["flagged"]), 2)
        self.assertIn("share email", b["flagged"][0]["reason"])

    def test_okta_side_duplicate_login_case_insensitive(self):
        b = iu.match_users([ou("A@example.com", email="1@x.com"),
                            ou("a@example.com", email="2@x.com")], [])
        self.assertEqual(b["to_create"], [])

    def test_several_entra_users_with_same_mail_is_ambiguous(self):
        entra = [{"userPrincipalName": "q1@example.com", "mail": "q@example.com"},
                 {"userPrincipalName": "q2@example.com", "mail": "q@example.com"}]
        b = iu.match_users([ou("new@example.com", email="q@example.com")], entra)
        self.assertIn("ambiguous", b["flagged"][0]["reason"])

    def test_guest_mail_is_not_a_match_candidate(self):
        entra = [{"userPrincipalName": "q_x.com#EXT#@t.onmicrosoft.com",
                  "mail": "q@example.com", "userType": "Guest"}]
        b = iu.match_users([ou("q@example.com")], entra)
        self.assertEqual(len(b["to_create"]), 1)

    def test_unknown_status_is_flagged(self):
        b = iu.match_users([ou("a@example.com", status="WEIRD")], [])
        self.assertIn("no mapping", b["flagged"][0]["reason"])

    def test_federated_domain_flagged_or_given_immutable_id(self):
        domains = [{"id": "example.com", "isVerified": True,
                    "authenticationType": "Federated"}]
        b = {"matched": [], "flagged": [],
             "to_create": [{"user": ou("a@example.com")}]}
        iu.domain_preflight(b, domains, None, lambda m: None)
        self.assertIn("federated", b["flagged"][0]["reason"])
        b = {"matched": [], "flagged": [],
             "to_create": [{"user": ou("a@example.com", objectGUID=GUID)}]}
        iu.domain_preflight(b, domains, "objectGUID", lambda m: None)
        self.assertEqual(b["to_create"][0]["immutableId"],
                         "LDqLb04dWk+LfJ0OHyo7TA==")

    def test_unverified_domain_flagged(self):
        b = {"matched": [], "flagged": [],
             "to_create": [{"user": ou("a@other.com")}]}
        iu.domain_preflight(b, [{"id": "other.com", "isVerified": False}],
                            None, lambda m: None)
        self.assertIn("not a verified domain", b["flagged"][0]["reason"])


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.inv = os.path.join(d, "inv.json")
        self.journal = os.path.join(d, "j.jsonl")
        self.audit = os.path.join(d, "a.jsonl")
        self.taps = os.path.join(d, "taps.tsv")
        self.report = os.path.join(d, "report.json")
        save_inventory({"source": {"oktaOrgId": "00oACME"}, "users": [
            ou("ada@example.com", countryCode="GB"),
            ou("grace@example.com", status="STAGED"),
            ou("mary@example.com", status="LOCKED_OUT"),
        ], "groups": [], "apps": []}, self.inv)

    def tearDown(self):
        self.tmp.cleanup()

    def apply(self, fake, *extra, expect=TENANT):
        argv = ["--inventory", self.inv, "--live", "--apply", "--yes",
                "--journal", self.journal, "--audit-log", self.audit,
                "--report", self.report, *extra]
        if expect:
            argv += ["--expect-tenant", expect]
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = iu.main(argv, graph_client=fake.client())
        return rc, out.getvalue(), err.getvalue()

    def test_refuses_without_tenant_or_tap_choice(self):
        fake = FakeGraph()
        self.assertEqual(self.apply(fake, "--no-tap", expect=None)[0], 2)
        self.assertEqual(self.apply(fake)[0], 2)          # no TAP destination
        self.assertEqual(self.apply(fake, "--show-taps", "-q")[0], 2)
        self.assertEqual(fake.created_users, [])

    def test_creates_users_with_status_policy_and_writes_taps_to_file_only(self):
        fake = FakeGraph()
        rc, out, _ = self.apply(fake, "--tap-file", self.taps,
                                "--usage-location", "US")
        self.assertEqual(rc, 0)
        by_upn = {u["userPrincipalName"]: u for u in fake.created_users}
        self.assertEqual(set(by_upn), {"ada@example.com", "grace@example.com",
                                       "mary@example.com"})
        self.assertTrue(by_upn["ada@example.com"]["accountEnabled"])
        self.assertEqual(by_upn["ada@example.com"]["usageLocation"], "GB")
        self.assertEqual(by_upn["mary@example.com"]["usageLocation"], "US")
        self.assertTrue(by_upn["mary@example.com"]["accountEnabled"])
        self.assertFalse(by_upn["grace@example.com"]["accountEnabled"])
        # TAPs only for enabled users, only in the 0600 file.
        self.assertEqual(len(fake.taps), 2)
        tap_values = [t["temporaryAccessPass"] for _, t in fake.taps]
        for v in tap_values:
            self.assertNotIn(v, out)
            self.assertNotIn(v, open(self.report).read())
            self.assertNotIn(v, open(self.audit).read())
        self.assertEqual(stat.S_IMODE(os.stat(self.taps).st_mode), 0o600)
        self.assertEqual(len(open(self.taps).read().splitlines()), 2)

    def test_quiet_never_prints_taps(self):
        fake = FakeGraph()
        rc, out, _ = self.apply(fake, "--tap-file", self.taps, "-q")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_show_taps_prints_them(self):
        fake = FakeGraph()
        rc, out, _ = self.apply(fake, "--show-taps")
        self.assertEqual(out.count("TAP for "), 2)

    def test_failed_tap_is_retried_on_rerun_without_recreating(self):
        fake = FakeGraph()
        fake.tap_disabled = True                      # TAP policy switched off
        rc, out, _ = self.apply(fake, "--tap-file", self.taps)
        self.assertEqual(rc, 0)
        self.assertIn("TAP failed", out)
        self.assertEqual(fake.taps, [])
        n_users = len(fake.created_users)
        fake.tap_disabled = False                     # admin fixes the policy
        rc, out, _ = self.apply(fake, "--tap-file", self.taps)
        self.assertEqual(rc, 0)
        self.assertEqual(len(fake.created_users), n_users)   # nothing re-created
        self.assertEqual(len(fake.taps), 2)                  # TAPs issued now
        self.assertEqual(len(open(self.taps).read().splitlines()), 2)

    def test_interrupted_create_is_recovered_and_gets_tap(self):
        fake = FakeGraph(users=[{"id": "e-ada", "userPrincipalName": "ada@example.com",
                                 "mail": "ada@example.com", "givenName": "T",
                                 "surname": "U", "accountEnabled": True}])
        from journal import Journal
        Journal(self.journal, binding={"script": "import_users",
                                       "entraTenantId": TENANT,
                                       "oktaSource": "00oACME"}
                ).record("ada@example.com", "pending")
        rc, out, _ = self.apply(fake, "--tap-file", self.taps)
        self.assertEqual(rc, 0)
        self.assertIn("recovered interrupted create", out)
        self.assertIn("e-ada", [uid for uid, _ in fake.taps])
        self.assertNotIn("ada@example.com",
                         [u["userPrincipalName"] for u in fake.created_users])

    def test_one_bad_user_does_not_stop_the_batch(self):
        fake = FakeGraph()
        fake.fail_user_create = {"grace@example.com"}
        rc, out, _ = self.apply(fake, "--no-tap")
        self.assertEqual(rc, 0)
        self.assertEqual(len(fake.created_users), 2)
        self.assertIn("ERROR creating grace@example.com", out)
        rep = json.load(open(self.report))
        self.assertIn("statusPolicy", rep)

    def test_journal_from_other_tenant_is_refused(self):
        self.apply(FakeGraph(), "--no-tap")
        other_id = "22222222-2222-2222-2222-222222222222"
        other = FakeGraph(tenant_id=other_id)
        rc, _, err = self.apply(other, "--no-tap", expect=other_id)
        self.assertEqual(rc, 2)
        self.assertIn("different run context", err)
        self.assertEqual(other.created_users, [])


if __name__ == "__main__":
    unittest.main()
