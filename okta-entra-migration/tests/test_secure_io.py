"""Unit tests: secret scrubbing + atomic 0600 writes."""

import csv
import io
import json
import os
import stat
import tempfile
import unittest

import _paths  # noqa: F401
from secure_io import (scrub_secrets, write_json, atomic_write_text,
                       csv_writer, REDACTED)


class ScrubTest(unittest.TestCase):
    def test_secret_keys_redacted_recursively(self):
        obj = {"user": {"passwordProfile": {"password": "hunter2"},
                        "name": "ada"},
               "items": [{"temporaryAccessPass": "tap-x"}],
               "clientSecret": "s3cr3t"}
        out = scrub_secrets(obj)
        blob = json.dumps(out)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("tap-x", blob)
        self.assertNotIn("s3cr3t", blob)
        self.assertEqual(out["user"]["name"], "ada")
        self.assertEqual(out["clientSecret"], REDACTED)

    def test_case_insensitive(self):
        self.assertEqual(scrub_secrets({"Password": "x"})["Password"],
                         REDACTED)

    def test_non_secret_data_untouched(self):
        obj = {"login": "ada@example.com", "n": 3, "ok": True}
        self.assertEqual(scrub_secrets(obj), obj)


class AtomicWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, name):
        return os.path.join(self.tmp.name, name)

    def test_write_json_0600_and_scrubbed(self):
        p = self.p("r.json")
        write_json(p, {"a": 1, "password": "nope"})
        data = json.load(open(p))
        self.assertEqual(data["password"], REDACTED)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_write_text_0600(self):
        p = self.p("r.txt")
        atomic_write_text(p, "hello")
        self.assertEqual(open(p).read(), "hello")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_write_csv_0600(self):
        p = self.p("r.csv")
        with csv_writer(p, ["a"]) as w:
            w.writeheader()
            w.writerow({"a": "1"})
        rows = list(csv.DictReader(open(p)))
        self.assertEqual(rows[0]["a"], "1")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_no_temp_files_left_behind(self):
        p = self.p("r.json")
        write_json(p, {"a": 1})
        leftovers = [f for f in os.listdir(self.tmp.name)
                     if f.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_stdout_dash(self):
        buf = io.StringIO()
        import sys
        old = sys.stdout
        sys.stdout = buf
        try:
            atomic_write_text("-", "hi")
        finally:
            sys.stdout = old
        self.assertEqual(buf.getvalue(), "hi")


if __name__ == "__main__":
    unittest.main()
