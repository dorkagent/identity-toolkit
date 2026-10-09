"""Secure output helpers for the toolkit.

Every file this toolkit writes goes through here:

* **0600 permissions** -- reports and plans can carry user lists, group
  memberships and tenant structure; they are never world-readable.
* **Atomic writes** -- data is written to a temp file in the same directory
  and moved into place with ``os.replace``; an interrupted run cannot leave
  a half-written file behind.
* **Secret scrubbing** -- ``write_json`` strips secret-bearing keys
  (passwords, tokens, TAPs) before serialization. Secrets are shown once on
  stdout or written to an explicitly requested 0600 file -- never baked
  into reports.
* **CSV cells can't become formulas** -- app labels and token names come
  from Okta and end up in spreadsheets; a cell starting with = + - @ (or a
  tab / carriage return) is prefixed with a quote.
* ``-`` as a path means stdout (no literal file named ``-`` is created).
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import sys
import tempfile

REDACTED = "[REDACTED]"

# Key names treated as secret-bearing anywhere they appear in a report
# or plan structure. Compared case-insensitively.
SECRET_KEY_NAMES = frozenset({
    "temppassword",
    "password",
    "passwordprofile",
    "temporaryaccesspass",
    "clientsecret",
    "secret",
    "apitoken",
    "accesstoken",
    "refreshtoken",
    "privatekey",
    "seed",
    "totpsecret",
})


def scrub_secrets(obj):
    """Return a copy of *obj* with secret-bearing values redacted."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if k.lower() in SECRET_KEY_NAMES
                else scrub_secrets(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [scrub_secrets(v) for v in obj]
    return obj


def atomic_write_bytes(path: str, data: bytes, mode: int = 0o600) -> None:
    """Write *data* to *path* atomically with the given permission bits."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: str, text: str, mode: int = 0o600) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def write_json(path: str | None, obj, scrub: bool = True,
               mode: int = 0o600) -> None:
    """Serialize *obj* as JSON to *path* (0600, atomic, secrets scrubbed)."""
    if path is None:
        return
    if scrub:
        obj = scrub_secrets(obj)
    atomic_write_text(path, json.dumps(obj, indent=2, default=str) + "\n",
                      mode)


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Neutralise spreadsheet formula injection in one CSV cell."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


class SafeDictWriter(csv.DictWriter):
    def writerow(self, rowdict):
        return super().writerow({k: csv_safe(v) for k, v in rowdict.items()})

    def writerows(self, rowdicts):
        for row in rowdicts:
            self.writerow(row)


@contextlib.contextmanager
def csv_writer(path: str | None, fieldnames: list[str]):
    """Yield a csv.DictWriter; file output is atomic + 0600, ``-``/None = stdout."""
    if path is None or path == "-":
        yield SafeDictWriter(sys.stdout, fieldnames=fieldnames)
        return
    buf = io.StringIO()
    yield SafeDictWriter(buf, fieldnames=fieldnames)
    atomic_write_text(path, buf.getvalue())
