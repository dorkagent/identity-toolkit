"""Append-only audit trail for mutating toolkit runs.

The journal (lib/journal.py) is a per-script resume ledger: it records
what *this script* finished so a rerun can skip it. The audit log answers
the compliance question: *who did what, when, against which tenant* --
across every script, in one human-readable JSONL file.

Each record: ts, script, actor, tenant, action, targetType, targetId,
targetName, detail. 0600 permissions, O_APPEND writes (safe for
concurrent scripts appending to the shared default file).

The audit log never carries secrets: TAP values, passwords and tokens
are recorded as "issued" with their id, never their value.
"""

from __future__ import annotations

import getpass
import json
import os
from datetime import datetime, timezone

AUDIT_VERSION = 1


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "?"


class AuditLog:
    """Append-only JSONL audit log (0600). ``path=None`` disables."""

    def __init__(self, path: str | None, script: str = "",
                 tenant: str = "", actor: str | None = None):
        self.path = path
        self.script = script
        self.tenant = tenant
        self.actor = actor if actor is not None else _actor()

    def record(self, action: str, target_type: str = "",
               target_id: str = "", target_name: str = "",
               detail: dict | None = None) -> None:
        rec = {
            "v": AUDIT_VERSION,
            "ts": _utcnow(),
            "script": self.script,
            "actor": self.actor,
            "tenant": self.tenant,
            "action": action,
            "targetType": target_type,
            "targetId": target_id or "",
            "targetName": target_name or "",
            "detail": detail or {},
        }
        if self.path:
            fd = os.open(self.path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.fchmod(fd, 0o600)  # tighten pre-existing lax files
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass  # os.fdopen() closes the fd itself on failure
                raise
