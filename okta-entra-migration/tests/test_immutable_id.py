"""Unit tests: ImmutableID / source-anchor verifier.

The core computation is verified against Microsoft's documentation, not
model memory:
  - Learn: ImmutableID is "the Base64 string representation of the
    mS-Ds-ConsistencyGUID attribute (or ObjectGUID depending on the
    configuration)".
  - The canonical hard-match recalculation is the PowerShell
        [System.Convert]::ToBase64String($guid.ToByteArray())
    and .NET Guid.ToByteArray() serializes GUID fields little-endian,
    which is Python's uuid.UUID(...).bytes_le.
"""

import unittest

import _paths  # noqa: F401
import verify_immutable_ids as vii

# Fixed vector: GUID -> expected ImmutableID (base64 of bytes_le).
GUID = "6F8B3A2C-1D4E-4F5A-8B7C-9D0E1F2A3B4C"
EXPECTED = "LDqLb04dWk+LfJ0OHyo7TA=="


def okta(login, **kw):
    u = {"id": "00u" + login, "login": login, "email": login,
         "credentialProvider": "ACTIVE_DIRECTORY",
         "profile": {"objectGUID": GUID}}
    u.update(kw)
    if "profile" in kw:
        u["profile"] = kw["profile"]
    return u


def entra(upn, immutable_id="sentinel"):
    u = {"id": "e-" + upn, "userPrincipalName": upn, "mail": upn}
    if immutable_id != "sentinel":
        u["onPremisesImmutableId"] = immutable_id
    return u


class ComputationTest(unittest.TestCase):
    def test_known_vector(self):
        self.assertEqual(vii.immutable_id_from_guid(GUID), EXPECTED)

    def test_case_and_whitespace_tolerant(self):
        self.assertEqual(
            vii.immutable_id_from_guid("  " + GUID.lower() + "\n"),
            EXPECTED)

    def test_rejects_non_guid(self):
        with self.assertRaises(ValueError):
            vii.immutable_id_from_guid("not-a-guid")


class VerdictTest(unittest.TestCase):
    def verify(self, okta_users, entra_users, **kw):
        return vii.verify_users(okta_users, entra_users, "objectGUID",
                                **kw)["results"]

    def test_match(self):
        r = self.verify([okta("a@x.y")], [entra("a@x.y", EXPECTED)])
        self.assertEqual(r[0]["verdict"], "match")

    def test_mismatch(self):
        r = self.verify([okta("a@x.y")], [entra("a@x.y", "AAAAAAAAAAAAAAAAAAAAAA==")])
        self.assertEqual(r[0]["verdict"], "mismatch")
        self.assertIn("duplicate", r[0]["detail"])

    def test_entra_missing_immutableid(self):
        r = self.verify([okta("a@x.y")], [entra("a@x.y", None)])
        self.assertEqual(r[0]["verdict"], "entra-missing-immutableid")
        self.assertEqual(r[0]["expectedImmutableId"], EXPECTED)

    def test_no_entra_user(self):
        r = self.verify([okta("a@x.y")], [])
        self.assertEqual(r[0]["verdict"], "no-entra-user")

    def test_no_anchor(self):
        r = self.verify([okta("a@x.y", profile={})], [])
        self.assertEqual(r[0]["verdict"], "no-anchor")

    def test_bad_anchor(self):
        r = self.verify([okta("a@x.y", profile={"objectGUID": "E12345"})],
                      [])
        self.assertEqual(r[0]["verdict"], "bad-anchor")

    def test_non_ad_skipped_by_default(self):
        ok = okta("a@x.y", credentialProvider="OKTA")
        rep = vii.verify_users([ok], [], "objectGUID", ad_only=True)
        self.assertEqual(rep["checked"], 0)
        self.assertEqual(rep["skippedNonAd"], 1)

    def test_all_users_flag_includes_okta_mastered(self):
        ok = okta("a@x.y", credentialProvider="OKTA")
        rep = vii.verify_users([ok], [], "objectGUID", ad_only=False)
        self.assertEqual(rep["checked"], 1)

    def test_matched_by_email_when_upn_differs(self):
        ou = okta("old@x.y")
        ou["email"] = "new@x.y"
        r = self.verify([ou], [entra("new@x.y", EXPECTED)])
        self.assertEqual(r[0]["verdict"], "match")

    def test_exit_code_counts_problems(self):
        rep = vii.verify_users([okta("a@x.y")], [entra("a@x.y", EXPECTED)],
                               "objectGUID")
        bad = sum(n for v, n in rep["counts"].items() if v != "match")
        self.assertEqual(bad, 0)


if __name__ == "__main__":
    unittest.main()
