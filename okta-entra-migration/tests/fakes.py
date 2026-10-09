"""In-memory stand-ins for the Okta and Graph HTTP APIs.

The real OktaClient / GraphClient classes run unchanged on top of these:
only the ``requests.Session`` is swapped. Response shapes follow the Okta
Management OpenAPI spec and the Microsoft Graph v1.0 docs, so a test that
passes here exercises the same request paths, bodies and paging the
scripts use against a real tenant.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import uuid

import requests


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None, links=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.links = links or {}
        self.text = json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Routes requests to ``handler(method, url, params, json)``."""

    def __init__(self, handler):
        self.handler = handler
        self.headers = {}
        self.calls = []

    def request(self, method, url, params=None, json=None, timeout=None):
        self.calls.append((method, url, dict(params or {}), json))
        return self.handler(method, url, dict(params or {}), json)

    def post(self, url, data=None, timeout=None):
        self.calls.append(("POST", url, {}, data))
        return self.handler("POST", url, {}, data)


# ---------------------------------------------------------------- Okta

class FakeOkta:
    """Minimal Okta org: collections keyed by API path, cursor paging.

    ``errors`` maps a path (optionally with ``?type=X``) to a status code.
    ``fail_after`` makes one path return 401 after N successful calls,
    to simulate a token being revoked mid-export.
    """

    BASE = "https://acme.okta.com"

    def __init__(self, data: dict, page_size: int = 2, errors=None):
        self.data = data
        self.page_size = page_size
        self.errors = dict(errors or {})
        self.session = FakeSession(self.handle)
        self.hits: dict[str, int] = {}
        self.fail_after: dict[str, int] = {}

    def handle(self, method, url, params, body):
        assert method == "GET", f"exporter must only read, got {method} {url}"
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        q = dict(urllib.parse.parse_qsl(parsed.query))
        q.update({k: str(v) for k, v in params.items()})
        self.hits[path] = self.hits.get(path, 0) + 1
        if path in self.fail_after and self.hits[path] > self.fail_after[path]:
            return FakeResponse(401, {"errorCode": "E0000011"})
        key = path + (f"?type={q['type']}" if "type" in q else "")
        if key in self.errors:
            return FakeResponse(self.errors[key], {"errorCode": "E0000002",
                                                   "errorSummary": "nope"})
        if path == "/api/v1/org":
            return FakeResponse(200, self.data["org"])
        if path == "/api/v1/users" and "search" in q:
            items = self.data.get("deprovisioned", [])
        elif path == "/api/v1/policies":
            items = self.data.get("policies", {}).get(q.get("type"), [])
        else:
            if path not in self.data:
                return FakeResponse(404, {"errorCode": "E0000007"})
            items = self.data[path]
        start = int(q.get("after", 0))
        page = items[start:start + self.page_size]
        links = {}
        if start + self.page_size < len(items):
            nq = dict(q, after=str(start + self.page_size))
            links["next"] = {"url": f"{self.BASE}{path}?"
                                    f"{urllib.parse.urlencode(nq)}"}
        return FakeResponse(200, page, links=links)


# ---------------------------------------------------------------- Graph

class FakeGraph:
    """Minimal Entra tenant behind Graph v1.0 paths the kit calls."""

    TENANT = "11111111-2222-3333-4444-555555555555"

    def __init__(self, users=None, groups=None, domains=None,
                 tenant_id=None, page_size=2):
        self.tenant_id = tenant_id or self.TENANT
        self.users = list(users or [])
        self.groups = list(groups or [])
        self.members: dict[str, set] = {}
        self.domains = list(domains or [{"id": "example.com",
                                         "isVerified": True,
                                         "authenticationType": "Managed"}])
        self.page_size = page_size
        self.session = FakeSession(self.handle)
        self.created_users, self.created_groups = [], []
        self.patches, self.ref_posts, self.taps = [], [], []
        self.fail_tap_for: set[str] = set()
        self.tap_disabled = False
        self.fail_user_create: set[str] = set()
        self.reject_batches = False

    # paging helper: Graph pages via @odata.nextLink
    def _page(self, url, items, params):
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query))
        start = int(q.get("$skiptoken", 0))
        body = {"value": items[start:start + self.page_size]}
        if start + self.page_size < len(items):
            body["@odata.nextLink"] = (
                f"https://graph.microsoft.com/v1.0{parsed.path.replace('/v1.0', '')}"
                f"?$skiptoken={start + self.page_size}")
        return FakeResponse(200, body)

    def handle(self, method, url, params, body):
        if "login.microsoftonline.com" in url:
            return FakeResponse(200, {"access_token": "fake-token"})
        path = urllib.parse.urlparse(url).path.replace("/v1.0", "")
        if method == "GET" and path == "/organization":
            return FakeResponse(200, {"value": [{"id": self.tenant_id,
                                                 "displayName": "Contoso Lab"}]})
        if method == "GET" and path == "/users":
            return self._page(url, self.users, params)
        if method == "GET" and path == "/domains":
            return self._page(url, self.domains, params)
        if method == "GET" and path == "/groups":
            return self._page(url, self.groups, params)
        m = re.fullmatch(r"/groups/([^/]+)/members", path)
        if method == "GET" and m:
            ids = sorted(self.members.get(m.group(1), set()))
            return self._page(url, [{"id": i} for i in ids], params)
        if method == "POST" and path == "/users":
            if body["userPrincipalName"] in self.fail_user_create:
                return FakeResponse(400, {"error": {"code": "Request_BadRequest",
                                                    "message": "bad user"}})
            for req in ("accountEnabled", "displayName", "mailNickname",
                        "passwordProfile", "userPrincipalName"):
                if req not in body:
                    return FakeResponse(400, {"error": {
                        "code": "Request_BadRequest",
                        "message": f"missing {req}"}})
            new = dict(body, id=str(uuid.uuid4()))
            new.pop("passwordProfile")
            self.users.append(new)
            self.created_users.append(body)
            return FakeResponse(201, new)
        if method == "POST" and path == "/groups":
            for req in ("displayName", "mailEnabled", "mailNickname",
                        "securityEnabled"):
                if req not in body:
                    return FakeResponse(400, {"error": {
                        "code": "Request_BadRequest",
                        "message": f"missing {req}"}})
            new = dict(body, id=str(uuid.uuid4()))
            self.groups.append(new)
            self.created_groups.append(body)
            return FakeResponse(201, new)
        m = re.fullmatch(r"/groups/([^/]+)", path)
        if method == "PATCH" and m:
            refs = body["members@odata.bind"]
            self.patches.append((m.group(1), refs))
            current = self.members.setdefault(m.group(1), set())
            ids = [r.rsplit("/", 1)[1] for r in refs]
            if self.reject_batches or len(ids) > 20 or any(i in current for i in ids):
                return FakeResponse(400, {"error": {
                    "code": "Request_BadRequest",
                    "message": "One or more added object references "
                               "already exist"}})
            current.update(ids)
            return FakeResponse(204)
        m = re.fullmatch(r"/groups/([^/]+)/members/\$ref", path)
        if method == "POST" and m:
            mid = body["@odata.id"].rsplit("/", 1)[1]
            self.ref_posts.append((m.group(1), mid))
            current = self.members.setdefault(m.group(1), set())
            if mid in current:
                return FakeResponse(400, {"error": {"message": "already exists"}})
            current.add(mid)
            return FakeResponse(204)
        m = re.fullmatch(r"/users/([^/]+)/authentication/"
                         r"temporaryAccessPassMethods", path)
        if method == "POST" and m:
            if self.tap_disabled or m.group(1) in self.fail_tap_for:
                return FakeResponse(403, {"error": {"code": "Forbidden",
                                                    "message": "TAP policy off"}})
            tap = {"id": str(uuid.uuid4()),
                   "temporaryAccessPass": f"TAP-{m.group(1)[:8]}",
                   "lifetimeInMinutes": body["lifetimeInMinutes"]}
            self.taps.append((m.group(1), tap))
            return FakeResponse(201, tap)
        return FakeResponse(404, {"error": {"code": "NotFound",
                                            "message": f"{method} {path}"}})

    def client(self):
        import graph_api
        return graph_api.GraphClient(self.tenant_id, "client", "secret",
                                     session=self.session,
                                     sleep=lambda s: None)
