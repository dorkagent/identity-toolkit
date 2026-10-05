"""Unit tests: journal resume semantics + audit trail (P0-4, P0-7)."""

import json
import os
import stat
import tempfile
import unittest

import _paths  # noqa: F401
from journal import Journal, OK, ERROR, SKIPPED
from audit import AuditLog


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "j.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ok_and_skipped_are_terminal(self):
        j = Journal(self.path)
        j.record("a", OK)
        j.record("b", SKIPPED, "exists")
        j.record("c", ERROR, "boom")
        self.assertTrue(j.completed("a"))
        self.assertTrue(j.completed("b"))
        self.assertFalse(j.completed("c"))
        self.assertFalse(j.completed("missing"))

    def test_latest_record_wins(self):
        j = Journal(self.path)
        j.record("a", ERROR, "first fail")
        j.record("a", OK, {"entraId": "x"})
        self.assertTrue(j.completed("a"))
        self.assertEqual(j.counts(), {"ok": 1, "error": 0, "skipped": 0})

    def test_resume_across_instances(self):
        Journal(self.path).record("a", OK)
        j2 = Journal(self.path)
        self.assertTrue(j2.completed("a"))

    def test_corrupt_lines_tolerated(self):
        with open(self.path, "w") as fh:
            fh.write('{"key": "a", "status": "ok"}\nGARBAGE\n'
                     '{"key": "b", "status": "error"}\n')
        j = Journal(self.path)
        self.assertTrue(j.completed("a"))
        self.assertFalse(j.completed("b"))

    def test_permissions_0600_and_tightened(self):
        with open(self.path, "w") as fh:
            fh.write("")
        os.chmod(self.path, 0o644)
        Journal(self.path).record("a", OK)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_disabled_journal_is_memory_only(self):
        j = Journal(None)
        j.record("a", OK)
        self.assertTrue(j.completed("a"))


class AuditLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "a.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_record_shape(self):
        AuditLog(self.path, script="s", tenant="t",
                 actor="op").record("create-user", "user", "u1", "n",
                                    {"oktaId": "00u1"})
        rec = json.loads(open(self.path).readline())
        for f in ("ts", "script", "actor", "tenant", "action",
                  "targetType", "targetId", "targetName", "detail"):
            self.assertIn(f, rec)
        self.assertEqual((rec["script"], rec["tenant"], rec["actor"],
                          rec["action"]),
                         ("s", "t", "op", "create-user"))

    def test_append_only_and_0600(self):
        al = AuditLog(self.path, script="s")
        al.record("a")
        al.record("b")
        self.assertEqual(len(open(self.path).readlines()), 2)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
