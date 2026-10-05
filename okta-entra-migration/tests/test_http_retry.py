"""Unit tests: rate-limit math (P0-3). No network; pure functions only."""

import time
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import _paths  # noqa: F401  (path setup)
from http_retry import retry_after_seconds, okta_reset_wait_seconds


class RetryAfterTest(unittest.TestCase):
    def test_delta_seconds(self):
        w = retry_after_seconds("7", attempt=0)
        self.assertGreaterEqual(w, 7.0)
        self.assertLess(w, 8.1)  # jitter <= 1s

    def test_delta_seconds_capped(self):
        self.assertLessEqual(retry_after_seconds("9999", 0), 61.0)

    def test_http_date(self):
        future = datetime.now(timezone.utc) + timedelta(seconds=30)
        w = retry_after_seconds(format_datetime(future), attempt=0)
        self.assertGreaterEqual(w, 25.0)
        self.assertLessEqual(w, 61.0)

    def test_past_http_date_clamps_to_zero(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=30)
        w = retry_after_seconds(format_datetime(past), attempt=0)
        self.assertLess(w, 1.1)

    def test_missing_header_backoff(self):
        w0 = retry_after_seconds(None, attempt=0)
        w2 = retry_after_seconds(None, attempt=2)
        self.assertGreaterEqual(w0, 5.0)     # base * 2**0
        self.assertGreaterEqual(w2, 20.0)    # base * 2**2

    def test_garbage_header_backoff(self):
        w = retry_after_seconds("not-a-time", attempt=1)
        self.assertGreaterEqual(w, 10.0)


class OktaResetTest(unittest.TestCase):
    def test_epoch_waits_until_reset(self):
        # x-rate-limit-reset is UTC epoch seconds: sleep until then,
        # NOT the epoch value as a duration.
        reset_at = int(time.time()) + 45
        w = okta_reset_wait_seconds(str(reset_at), attempt=0)
        self.assertGreaterEqual(w, 40.0)
        self.assertLess(w, 50.0)  # jitter <= 2s; would be ~huge if misread

    def test_past_epoch_no_wait(self):
        w = okta_reset_wait_seconds(str(int(time.time()) - 10), attempt=0)
        self.assertLess(w, 2.1)

    def test_missing_header_backoff(self):
        w = okta_reset_wait_seconds(None, attempt=2)
        self.assertGreaterEqual(w, 20.0)  # 5 * 2**2

    def test_garbage_header_backoff(self):
        w = okta_reset_wait_seconds("soon", attempt=0)
        self.assertGreaterEqual(w, 5.0)


if __name__ == "__main__":
    unittest.main()
