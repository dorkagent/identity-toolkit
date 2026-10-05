"""Checkpoint/resume journal for ``--apply`` batch runs.

Append-only JSONL: each line records one item's outcome (``ok`` / ``error``
/ ``skipped``). A rerun with the same ``--journal`` path skips items already
recorded ``ok``/``skipped`` and retries ``error`` items, so an interrupted
or partially failed run resumes instead of restarting from zero.

The journal file is created 0600 -- it can carry Entra object ids and
operator notes about tenant structure.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

OK = "ok"
ERROR = "error"
SKIPPED = "skipped"
COMPLETED = (OK, SKIPPED)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Journal:
    def __init__(self, path: str | None):
        self.path = path
        self.records: dict[str, dict] = {}
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
                    if rec.get("key") is not None:
                        self.records[rec["key"]] = rec

    def completed(self, key: str) -> bool:
        """True if *key* already reached a terminal good state."""
        rec = self.records.get(key)
        return rec is not None and rec.get("status") in COMPLETED

    def record(self, key: str, status: str, detail=None) -> None:
        rec: dict = {"key": key, "status": status, "ts": _utcnow()}
        if detail is not None:
            rec["detail"] = detail
        self.records[key] = rec
        if self.path:
            fd = os.open(self.path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                # Enforce 0600 even if the file already existed with
                # laxer permissions (O_CREAT mode only applies on create).
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
