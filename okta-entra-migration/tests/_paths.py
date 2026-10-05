"""Shared path setup for the toolkit test suite (stdlib unittest only)."""

import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (os.path.join(REPO, "lib"), REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

FIXTURES = os.path.join(REPO, "fixtures")
