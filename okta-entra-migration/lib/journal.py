"""Checkpoint/resume journal for ``--apply`` batch runs.

Append-only JSONL: each line records one item's outcome (``ok`` / ``error``
/ ``skipped``). A rerun with the same ``--journal`` path skips items already
recorded ``ok``/``skipped`` and retries ``error`` items, so an interrupted
or partially failed run resumes instead of starting over.

A journal can be *bound* to a context (script name, Entra tenant id, Okta
org). The binding is written as the first line. Opening a bound journal
with a different binding raises ``JournalMismatchError``, so a journal left
over from a lab run can't make a production run skip work it never did.
A journal that already has records but no binding is refused the same way.

The file is created 0600: it can carry Entra object ids.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

OK = "ok"
ERROR = "error"
SKIPPED = "skipped"
COMPLETED = (OK, SKIPPED)
HEADER_TYPE = "journal-binding"


class JournalMismatchError(RuntimeError):
    """The journal on disk belongs to a different tenant, org or script."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Journal:
    def __init__(self, path: str | None, binding: dict | None = None):
        self.path = path
        self.binding = dict(binding) if binding else None
        self.records: dict[str, dict] = {}
        found_binding = None
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("type") == HEADER_TYPE:
                        found_binding = rec.get("binding") or {}
                        continue
                    if rec.get("key") is not None:
                        self.records[rec["key"]] = rec
        if self.binding is not None and path:
            if found_binding is None and self.records:
                raise JournalMismatchError(
                    f"journal {path} has records but no tenant binding; it "
                    f"may be from another tenant. Move it aside or pass a "
                    f"different --journal path.")
            if found_binding is not None and found_binding != self.binding:
                diff = {k: (found_binding.get(k), self.binding.get(k))
                        for k in set(found_binding) | set(self.binding)
                        if found_binding.get(k) != self.binding.get(k)}
                raise JournalMismatchError(
                    f"journal {path} belongs to a different run context "
                    f"(field: journal value vs this run): {diff}. Refusing "
                    f"to resume from it.")
            if found_binding is None:
                self._append({"type": HEADER_TYPE, "binding": self.binding,
                              "ts": _utcnow()})

    def completed(self, key: str) -> bool:
        """True if *key* already reached a terminal good state."""
        rec = self.records.get(key)
        return rec is not None and rec.get("status") in COMPLETED

    def get(self, key: str) -> dict | None:
        return self.records.get(key)

    def record(self, key: str, status: str, detail=None) -> None:
        rec: dict = {"key": key, "status": status, "ts": _utcnow()}
        if detail is not None:
            rec["detail"] = detail
        self.records[key] = rec
        self._append(rec)

    def _append(self, rec: dict) -> None:
        if not self.path:
            return
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            # Enforce 0600 even if the file already existed with laxer
            # permissions (O_CREAT mode only applies on create).
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass  # os.fdopen() closes the fd itself on failure
            raise

    def counts(self) -> dict[str, int]:
        out = {OK: 0, ERROR: 0, SKIPPED: 0}
        for rec in self.records.values():
            if rec.get("status") in out:
                out[rec["status"]] += 1
        return out
