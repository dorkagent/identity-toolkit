"""Small helpers the scripts share: connecting, timestamps, log windows."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

from lib.okta_client import OktaAuthError, OktaClient

# Okta keeps System Log events for 90 days.
LOG_RETENTION_DAYS = 90


def connect() -> OktaClient:
    try:
        return OktaClient()
    except OktaAuthError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1) from e


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def log_window(days: float, now: datetime | None = None) -> tuple[str, str, bool]:
    """(since, until, clipped) for a lookback of `days`, capped at retention.

    clipped is True when the request asked for more history than Okta keeps.
    """
    now = now or datetime.now(UTC)
    clipped = days > LOG_RETENTION_DAYS
    days = min(days, LOG_RETENTION_DAYS)
    return utc_iso(now - timedelta(days=days)), utc_iso(now), clipped


def event_user(event: dict) -> dict:
    """The user an event is about: the actor if it is a User, else the first User target."""
    actor = event.get("actor") or {}
    if actor.get("type") == "User" or not actor.get("type"):
        return actor
    for t in event.get("target") or []:
        if t.get("type") == "User":
            return t
    return actor
