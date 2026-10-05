"""Shared 429/backoff helpers for the Okta and Graph API clients.

Okta and Microsoft Graph report rate limits differently:

* Okta ``x-rate-limit-reset`` is **UTC epoch seconds** (per Okta's rate-limit
  docs) -- the client must sleep until that timestamp, not treat it as a
  seconds-to-wait value.
* Graph ``Retry-After`` is delta-seconds per Microsoft's docs, but the HTTP
  spec also allows an HTTP-date; both forms are handled.

When a header is missing or unparseable, both clients fall back to
exponential backoff with jitter rather than crashing or hammering.
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def retry_after_seconds(value: str | None, attempt: int,
                        base: float = 5.0, cap: float = 60.0) -> float:
    """Seconds to wait after an HTTP 429 (Graph ``Retry-After`` style).

    * delta-seconds value -> that many seconds (capped)
    * HTTP-date value    -> seconds until that date, min 0 (capped)
    * missing/garbage    -> exponential backoff ``base * 2**attempt`` (capped)

    A small jitter is always added so concurrent workers don't retry in
    lockstep.
    """
    wait: float | None = None
    if value:
        text = value.strip()
        if text.isdigit():
            wait = float(text)
        else:
            try:
                reset_at = parsedate_to_datetime(text)
                if reset_at.tzinfo is None:
                    reset_at = reset_at.replace(tzinfo=timezone.utc)
                wait = (reset_at - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError):
                wait = None
    if wait is None:
        wait = base * (2 ** attempt)
    return min(max(wait, 0.0), cap) + random.uniform(0, 1)


def okta_reset_wait_seconds(value: str | None, attempt: int,
                            cap: float = 120.0) -> float:
    """Seconds to wait after an Okta 429.

    Okta's ``x-rate-limit-reset`` is UTC epoch seconds: wait until that
    timestamp (plus jitter). Missing/garbage -> exponential backoff.
    """
    wait: float | None = None
    if value:
        try:
            wait = int(value.strip()) - time.time()
        except (ValueError, AttributeError):
            wait = None
    if wait is None or wait <= 0:
        wait = 5.0 * (2 ** attempt) if wait is None else 0.0
    return min(max(wait, 0.0), cap) + random.uniform(0, 2)
