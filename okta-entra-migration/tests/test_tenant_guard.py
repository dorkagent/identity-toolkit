"""Unit tests: wrong-tenant protection + apply confirmation."""

import unittest

import _paths  # noqa: F401
from graph_api import GraphClient, TenantMismatchError
from okta_api import OktaClient, OrgMismatchError
from tenant_guard import confirm_apply


class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


class GraphNoInit(GraphClient):
    def __init__(self, tenant_id, org_id):
        self._tenant_id = tenant_id
        self._org_id = org_id

    def _request(self, method, path, params=None, data=None, retries=5):
        return FakeResp({"value": [{"id": self._org_id,
                                    "displayName": "Contoso"}]})


class OktaNoInit(OktaClient):
    def __init__(self, domain, subdomain):
        self.base_url = "https://" + domain
        self._subdomain = subdomain

    def _request(self, method, path, params=None, data=None, retries=5):
        return FakeResp({"id": "oo1", "subdomain": self._subdomain})


class VerifyTenantTest(unittest.TestCase):
    def test_match_returns_org(self):
        org = GraphNoInit("tid-1", "tid-1").verify_tenant()
        self.assertEqual(org["displayName"], "Contoso")

    def test_mismatch_raises(self):
        with self.assertRaises(TenantMismatchError) as cm:
            GraphNoInit("tid-1", "tid-2").verify_tenant()
        self.assertIn("GRAPH_TENANT_ID", str(cm.exception))

    def test_common_authority_skips_comparison(self):
        GraphNoInit("common", "any-tenant").verify_tenant()

    def test_case_insensitive(self):
        GraphNoInit("TID-1", "tid-1").verify_tenant()


class VerifyOrgTest(unittest.TestCase):
    def test_match(self):
        OktaNoInit("acme.okta.com", "acme").verify_org()

    def test_mismatch_raises(self):
        with self.assertRaises(OrgMismatchError) as cm:
            OktaNoInit("acme.okta.com", "evil").verify_org()
        self.assertIn("OKTA_DOMAIN", str(cm.exception))


class ConfirmApplyTest(unittest.TestCase):
    def test_yes_skips_prompt(self):
        self.assertTrue(confirm_apply("summary", True))

    def test_non_tty_without_yes_refuses(self):
        # Test runner stdin is not a TTY: must refuse, never hang.
        import sys
        self.assertFalse(sys.stdin.isatty())
        self.assertFalse(confirm_apply("summary", False))


if __name__ == "__main__":
    unittest.main()
