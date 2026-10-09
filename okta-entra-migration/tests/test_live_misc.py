"""Graph client behaviour, verify_immutable_ids --live, migrate_apps, journal binding."""

import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import _paths  # noqa: F401
import migrate_apps as ma
import verify_immutable_ids as vii
from fakes import FakeGraph, FakeResponse
from graph_api import GraphRequestError
from inventory import save_inventory
from journal import Journal, JournalMismatchError
from secure_io import csv_safe

GUID = "6F8B3A2C-1D4E-4F5A-8B7C-9D0E1F2A3B4C"
EXPECTED = "LDqLb04dWk+LfJ0OHyo7TA=="


class GraphClientTest(unittest.TestCase):
    def test_paging_follows_next_link(self):
        fake = FakeGraph(users=[{"id": str(i), "userPrincipalName": f"{i}@x"}
                                for i in range(5)], page_size=2)
        self.assertEqual(len(list(fake.client().list_users())), 5)

    def test_429_then_success_and_401_remint(self):
        fake = FakeGraph()
        seq = [FakeResponse(429, {}, headers={"Retry-After": "1"}),
               FakeResponse(401, {}),
               None]
        orig = fake.handle
        tokens = []

        def handle(method, url, params, body):
            if "login.microsoftonline.com" in url:
                tokens.append(1)
                return FakeResponse(200, {"access_token": "t"})
            if url.endswith("/organization") and seq:
                r = seq.pop(0)
                if r is not None:
                    return r
            return orig(method, url, params, body)
        fake.session.handler = handle
        c = fake.client()
        self.assertEqual(c.verify_tenant()["id"], FakeGraph.TENANT)
        self.assertEqual(len(tokens), 2)    # initial + one re-mint

    def test_error_carries_graph_message(self):
        fake = FakeGraph()
        with self.assertRaises(GraphRequestError) as cm:
            fake.client().create_group({"displayName": "x"})
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("missing mailEnabled", str(cm.exception))

    def test_add_members_rejects_more_than_20(self):
        with self.assertRaises(ValueError):
            FakeGraph().client().add_group_members("g", [str(i) for i in range(21)])


class VerifyImmutableLiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inv = os.path.join(self.tmp.name, "inv.json")
        save_inventory({"users": [{
            "id": "00u1", "login": "alan@example.com", "email": "alan@example.com",
            "credentialProvider": "ACTIVE_DIRECTORY", "status": "ACTIVE",
            "profile": {"objectGUID": GUID}}]}, self.inv)

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, fake, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = vii.main(["--inventory", self.inv, "--live", *extra],
                          graph_client=fake.client())
        return rc, out.getvalue(), err.getvalue()

    def test_live_run_reads_graph_and_matches(self):
        fake = FakeGraph(users=[{"id": "e1", "userPrincipalName": "alan@example.com",
                                 "onPremisesImmutableId": EXPECTED}])
        rc, out, _ = self.run_main(fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("match: 1", out)

    def test_expected_tenant_mismatch_exits_2(self):
        rc, _, err = self.run_main(FakeGraph(), "--expect-tenant",
                                   "00000000-0000-0000-0000-000000000000")
        self.assertEqual(rc, 2)
        self.assertIn("not the expected tenant", err)

    def test_shared_mail_is_ambiguous_not_matched(self):
        entra = [{"id": "a", "userPrincipalName": "x1@example.com",
                  "mail": "alan@example.com", "onPremisesImmutableId": EXPECTED},
                 {"id": "b", "userPrincipalName": "x2@example.com",
                  "mail": "alan@example.com"}]
        okta = [{"login": "old@example.com", "email": "alan@example.com",
                 "credentialProvider": "ACTIVE_DIRECTORY",
                 "profile": {"objectGUID": GUID}}]
        rep = vii.verify_users(okta, entra, "objectGUID")
        self.assertEqual(rep["results"][0]["verdict"], "ambiguous-email")


class MigrateAppsTest(unittest.TestCase):
    INV = {
        "source": {"oktaDomain": "https://acme.okta.com"},
        "users": [{"id": "00u1", "login": "a@x.com"}, {"id": "00u2", "login": "b@x.com"}],
        "groups": [{"id": "00g1", "name": "Eng"}],
        "apps": [{"id": "0oa1", "label": "=HYPERLINK(\"evil\")", "name": "s",
                  "signOnMode": "SAML_2_0", "status": "ACTIVE",
                  "sso": {"audience": "https://sp", "ssoAcsUrl": "https://sp/acs",
                          "oktaMetadataPath": "/api/v1/apps/0oa1/sso/saml/metadata"},
                  "assignedGroups": ["00g1"], "assignedUsers": ["00u1", "00u2"],
                  "assignedUsersDirect": ["00u1"]},
                 {"id": "0oa2", "label": "M365", "signOnMode": "WS_FEDERATION",
                  "assignedUsers": []}],
    }
    TENANT = "38d49456-0000-1111-2222-333344445555"

    def test_rows_use_real_saml_fields_and_tenant_guid(self):
        rows = ma.build_rows(self.INV, self.TENANT, {"0oa1": "owner@x.com"})
        r = rows[0]
        self.assertEqual(r["sp_acs_url"], "https://sp/acs")
        self.assertEqual(r["sp_entity_id"], "https://sp")
        self.assertEqual(r["owner"], "owner@x.com")
        self.assertEqual(r["entra_identifier"],
                         f"https://sts.windows.net/{self.TENANT}/")
        self.assertIn(f"/{self.TENANT}/federationmetadata", r["entra_metadata_url"])
        self.assertEqual(r["okta_metadata_path"],
                         "https://acme.okta.com/api/v1/apps/0oa1/sso/saml/metadata")
        self.assertEqual(r["assigned_users_direct"], "a@x.com")
        self.assertEqual(r["assigned_users_total"], 2)
        self.assertEqual(rows[1]["owner"], "MISSING")
        self.assertIn("federation", rows[1]["cutover_notes"])

    def test_domain_instead_of_guid_gives_placeholders(self):
        r = ma.build_rows(self.INV, "contoso.onmicrosoft.com")[0]
        self.assertIn("<tenant-guid>", r["entra_identifier"])

    def test_owner_csv_join_and_formula_escaping(self):
        with tempfile.TemporaryDirectory() as d:
            owners = os.path.join(d, "owners.csv")
            with open(owners, "w", newline="", encoding="utf-8") as fh:
                fh.write("app_name,owner\nM365,it@x.com\n")
            inv = os.path.join(d, "inv.json")
            save_inventory(dict(self.INV), inv)
            out = os.path.join(d, "map.csv")
            with redirect_stderr(io.StringIO()):
                ma.main(["--inventory", inv, "--owners", owners, "-o", out,
                         "--tenant", self.TENANT])
            rows = list(csv.DictReader(open(out, encoding="utf-8")))
        self.assertTrue(rows[0]["app_name"].startswith("'="))
        self.assertEqual(rows[1]["owner"], "it@x.com")
        self.assertEqual(csv_safe("@SUM(1)"), "'@SUM(1)")
        self.assertEqual(csv_safe("Slack"), "Slack")


class JournalBindingTest(unittest.TestCase):
    def test_binding_mismatch_and_unbound_records_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "j.jsonl")
            lab = {"script": "s", "entraTenantId": "lab"}
            Journal(p, binding=lab).record("a", "ok")
            self.assertTrue(Journal(p, binding=lab).completed("a"))
            with self.assertRaises(JournalMismatchError):
                Journal(p, binding={"script": "s", "entraTenantId": "prod"})
            p2 = os.path.join(d, "old.jsonl")
            Journal(p2).record("a", "ok")             # legacy, unbound
            with self.assertRaises(JournalMismatchError):
                Journal(p2, binding=lab)
            first = json.loads(open(p).readline())
            self.assertEqual(first["binding"], lab)


if __name__ == "__main__":
    unittest.main()
