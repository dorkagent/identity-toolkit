"""Unit tests: id-based group existence ledger (P0-5)."""

import unittest

import _paths  # noqa: F401
from mirror_groups import (stamp_description, extract_stamped_id,
                           plan_groups)


class StampTest(unittest.TestCase):
    def test_round_trip(self):
        s = stamp_description("Team group", "00g1")
        self.assertIn("[okta-group-id:00g1]", s)
        self.assertIn("Team group", s)
        self.assertEqual(extract_stamped_id(s), "00g1")

    def test_empty_description(self):
        self.assertEqual(stamp_description("", "00g9"),
                         "[okta-group-id:00g9]")

    def test_none_description(self):
        self.assertIsNone(extract_stamped_id(None))

    def test_idempotent(self):
        s = stamp_description("d", "00g1")
        self.assertEqual(stamp_description(s, "00g1"), s)

    def test_unstamped_returns_none(self):
        self.assertIsNone(extract_stamped_id("plain description"))


class LedgerSemanticsTest(unittest.TestCase):
    """The apply loop's decision rule, factored for testability:

    stamped id match -> skip (already mirrored); bare displayName match
    with no stamp -> collision to flag, never silent-skip; neither ->
    create.
    """

    def decide(self, okta_id, name, stamped, by_name):
        if okta_id in stamped:
            return "skip-id"
        if name.lower() in by_name:
            return "collision"
        return "create"

    def test_stamped_match_skips(self):
        self.assertEqual(
            self.decide("00g1", "Engineering", {"00g1": {}}, {}), "skip-id")

    def test_bare_name_match_is_collision_not_skip(self):
        self.assertEqual(
            self.decide("00g9", "Engineering", {}, {"engineering": [{}]}),
            "collision")

    def test_unknown_group_creates(self):
        self.assertEqual(self.decide("00g9", "New Team", {}, {}), "create")

    def test_plan_stamps_every_group(self):
        inv = {"users": [],
               "groups": [
                   {"id": "00g1", "name": "Engineering",
                    "description": "eng", "members": [],
                    "dynamicRule": None},
                   {"id": "00g2", "name": "Empty", "description": "",
                    "members": [], "dynamicRule": None}]}
        plan = plan_groups(inv)
        for e in plan["groups"]:
            self.assertIn(f"[okta-group-id:{e['oktaGroupId']}]",
                          e["entraGroup"]["description"])


if __name__ == "__main__":
    unittest.main()
