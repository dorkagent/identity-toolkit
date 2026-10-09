"""Test helpers: a fake Okta org that answers HTTP calls from canned data.

FakeOkta stands in for requests.Session. Routes are registered per
(method, path) and return JSON bodies, optional Link headers and status codes.
Every call is recorded so tests can assert on what was (or wasn't) sent.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from lib.okta_client import OktaClient  # noqa: E402

BASE = "https://example.okta.com"


def make_response(status=200, body=None, headers=None, url=BASE) -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r._content = b"" if body is None else json.dumps(body).encode()
    r.headers.update(headers or {})
    r.url = url
    return r


class FakeOkta:
    def __init__(self):
        self.routes: dict[tuple[str, str], object] = {}
        self.calls: list[dict] = []
        self.headers: dict = {}

    def add(self, method: str, path: str, handler):
        """handler: a body, a list of responses (served in order), or a callable(call) -> Response."""
        self.routes[(method.upper(), path)] = handler

    def pages(self, path: str, pages: list[list]):
        """Serve `pages` for GET path, linking each page to the next with ?after=N."""
        def handler(call):
            idx = int(call["params"].get("after", 0))
            headers = {}
            if idx + 1 < len(pages):
                q = {k: v for k, v in call["params"].items() if k != "after"}
                q["after"] = idx + 1
                headers["Link"] = f'<{BASE}{path}?{urlencode(q)}>; rel="next"'
            return make_response(200, pages[idx], headers, url=call["url"])
        self.add("GET", path, handler)

    # requests.Session interface used by OktaClient
    def request(self, method, url, params=None, json=None, timeout=None):
        parts = urlsplit(url)
        merged = dict(parse_qsl(parts.query))
        merged.update({k: str(v) for k, v in (params or {}).items()})
        call = {"method": method.upper(), "path": parts.path, "params": merged,
                "json": json, "url": url}
        self.calls.append(call)
        handler = self.routes.get((call["method"], parts.path))
        if handler is None:
            return make_response(404, {"errorSummary": f"no route {method} {parts.path}"}, url=url)
        if callable(handler):
            return handler(call)
        if isinstance(handler, list):
            if len(handler) > 1:
                return handler.pop(0)
            return handler[0]
        return make_response(200, handler, url=url)

    def post(self, url, data=None, headers=None, timeout=None):
        return self.request("POST", url, params=None, json=data)

    def writes(self) -> list[dict]:
        return [c for c in self.calls if c["method"] != "GET"]

    def called(self, method: str, path: str) -> list[dict]:
        return [c for c in self.calls if c["method"] == method and c["path"] == path]


@pytest.fixture
def fake():
    return FakeOkta()


@pytest.fixture
def client(fake, monkeypatch):
    monkeypatch.delenv("OKTA_CLIENT_ID", raising=False)
    return OktaClient(BASE, "test-token", session=fake, sleep=lambda s: None)


def user(uid, login, status="ACTIVE", last_login=None, created="2020-01-01T00:00:00.000Z", **profile):
    return {"id": uid, "status": status, "lastLogin": last_login, "created": created,
            "profile": {"login": login, "email": login, "firstName": "F", "lastName": "L", **profile}}


def group(gid, name, gtype="OKTA_GROUP"):
    return {"id": gid, "type": gtype, "profile": {"name": name}}
