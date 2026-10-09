"""Small Okta management API client shared by the Python scripts.

Credentials come from the environment, never from files in this repo.
Two auth modes are supported:

SSWS API token (simplest):
    OKTA_DOMAIN       https://your-org.okta.com
    OKTA_API_TOKEN    the token. It carries the full admin role of the user
                      who created it, so create it from a Read-Only Admin
                      account for the report-only scripts.

OAuth 2.0 service app with private_key_jwt (preferred by Okta):
    OKTA_DOMAIN
    OKTA_CLIENT_ID        client ID of an API Services app
    OKTA_PRIVATE_KEY      path to the PEM private key registered on that app
    OKTA_SCOPES           space-separated scopes, e.g. "okta.users.read okta.logs.read"
    OKTA_KEY_ID           optional, the "kid" of the key if the app has several

If both are set, OKTA_API_TOKEN wins. DPoP-bound tokens are not supported;
turn off "Require DPoP" on the service app if you use this mode.
"""

from __future__ import annotations

import os
import random
import time
import uuid

import requests

DEFAULT_TIMEOUT = 30
USER_AGENT = "okta-admin-scripts/0.2"

# Hard stop for any paginated read. At limit=200 this is two million objects,
# far beyond a normal org, so hitting it means something is looping.
DEFAULT_MAX_PAGES = 10_000


class OktaError(RuntimeError):
    """Base class for errors raised by this client."""


class OktaAuthError(OktaError):
    """Credentials are missing, or Okta rejected them (HTTP 401)."""


class OktaApiError(OktaError):
    """Okta returned an error status other than 401."""

    def __init__(self, status: int, method: str, path: str, body: str = ""):
        self.status = status
        self.method = method
        self.path = path
        self.body = body
        super().__init__(f"HTTP {status} on {method} {path}: {body[:300]}")


class OktaForbiddenError(OktaApiError):
    """HTTP 403. The credentials work but lack permission for this call."""


class OktaNotFoundError(OktaApiError):
    """HTTP 404."""


def quote_filter_value(value: str) -> str:
    """Escape a value for use inside double quotes in an Okta filter expression."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def rate_limit_wait(headers, now: float | None = None) -> float:
    """Seconds to wait after a 429.

    x-rate-limit-reset is a UTC epoch timestamp in seconds, not a duration,
    so the wait is reset minus now, clamped to 1-60 s.
    """
    now = time.time() if now is None else now
    raw = headers.get("x-rate-limit-reset") if headers else None
    try:
        wait = float(raw) - now
    except (TypeError, ValueError):
        wait = 5.0
    return max(1.0, min(wait, 60.0))


class OktaClient:
    def __init__(self, domain: str | None = None, api_token: str | None = None, *,
                 client_id: str | None = None, private_key: str | None = None,
                 scopes: str | None = None, key_id: str | None = None,
                 session: requests.Session | None = None,
                 max_pages: int = DEFAULT_MAX_PAGES, sleep=time.sleep):
        domain = (domain or os.environ.get("OKTA_DOMAIN") or "").strip().rstrip("/")
        if not domain:
            raise OktaAuthError("Set OKTA_DOMAIN, e.g. https://your-org.okta.com")
        if not domain.startswith("http"):
            domain = "https://" + domain
        self.base_url = domain
        self.max_pages = max_pages
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        })

        token = api_token or os.environ.get("OKTA_API_TOKEN")
        self._oauth = None
        self._access_token = None
        self._access_token_expiry = 0.0
        if token:
            self.auth_mode = "ssws"
            self.session.headers["Authorization"] = f"SSWS {token}"
            return

        client_id = client_id or os.environ.get("OKTA_CLIENT_ID")
        private_key = private_key or os.environ.get("OKTA_PRIVATE_KEY")
        scopes = scopes or os.environ.get("OKTA_SCOPES")
        key_id = key_id or os.environ.get("OKTA_KEY_ID")
        if client_id and private_key and scopes:
            self.auth_mode = "oauth"
            if os.path.isfile(private_key):
                with open(private_key, encoding="utf-8") as f:
                    private_key = f.read()
            self._oauth = {"client_id": client_id, "key": private_key,
                           "scopes": scopes, "kid": key_id}
            return

        raise OktaAuthError(
            "No credentials. Set OKTA_API_TOKEN, or OKTA_CLIENT_ID + "
            "OKTA_PRIVATE_KEY + OKTA_SCOPES for an OAuth service app.")

    # ---- OAuth (client_credentials + private_key_jwt) ----

    def _client_assertion(self) -> str:
        try:
            import jwt  # PyJWT, only needed for OAuth mode
        except ImportError as e:  # pragma: no cover - depends on environment
            raise OktaAuthError(
                "OAuth mode needs PyJWT and cryptography: "
                "pip install 'pyjwt[crypto]'") from e
        now = int(time.time())
        claims = {
            "iss": self._oauth["client_id"],
            "sub": self._oauth["client_id"],
            "aud": f"{self.base_url}/oauth2/v1/token",
            "iat": now,
            "exp": now + 300,
            "jti": uuid.uuid4().hex,
        }
        headers = {"kid": self._oauth["kid"]} if self._oauth["kid"] else None
        return jwt.encode(claims, self._oauth["key"], algorithm="RS256",
                          headers=headers)

    def _ensure_access_token(self):
        if self._oauth is None:
            return
        if self._access_token and time.time() < self._access_token_expiry - 60:
            return
        resp = self.session.post(
            f"{self.base_url}/oauth2/v1/token",
            data={
                "grant_type": "client_credentials",
                "scope": self._oauth["scopes"],
                "client_assertion_type":
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self._client_assertion(),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code != 200:
            raise OktaAuthError(
                f"Token request failed (HTTP {resp.status_code}): {resp.text[:300]}")
        body = resp.json()
        self._access_token = body["access_token"]
        self._access_token_expiry = time.time() + int(body.get("expires_in", 3600))
        self.session.headers["Authorization"] = f"Bearer {self._access_token}"

    # ---- core request ----

    def _request(self, method: str, path_or_url: str, params: dict | None = None,
                 data: dict | None = None, retries: int = 5) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else self.base_url + path_or_url
        path = url[len(self.base_url):] if url.startswith(self.base_url) else url
        last_error = None
        for attempt in range(retries):
            self._ensure_access_token()
            try:
                resp = self.session.request(method, url, params=params, json=data,
                                            timeout=DEFAULT_TIMEOUT)
            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = e
                self._sleep(min(2 ** attempt, 30) + random.uniform(0, 0.5))
                continue
            if resp.status_code == 429:
                self._sleep(rate_limit_wait(resp.headers) + random.uniform(0, 1))
                last_error = OktaApiError(429, method, path, resp.text)
                continue
            if resp.status_code >= 500:
                self._sleep(min(2 ** attempt, 30) + random.uniform(0, 0.5))
                last_error = OktaApiError(resp.status_code, method, path, resp.text)
                continue
            if resp.status_code == 401:
                raise OktaAuthError(
                    f"Okta rejected the credentials (HTTP 401) on {method} {path}.")
            if resp.status_code == 403:
                raise OktaForbiddenError(403, method, path, resp.text)
            if resp.status_code == 404:
                raise OktaNotFoundError(404, method, path, resp.text)
            if resp.status_code >= 400:
                raise OktaApiError(resp.status_code, method, path, resp.text)
            return resp
        raise OktaError(f"Gave up on {method} {path} after {retries} attempts: {last_error}")

    def get(self, path: str, params: dict | None = None):
        resp = self._request("GET", path, params=params)
        return resp.json() if resp.text else None

    def post(self, path: str, data: dict | None = None) -> dict:
        resp = self._request("POST", path, data=data)
        return resp.json() if resp.text else {}

    def put(self, path: str, data: dict | None = None) -> dict:
        resp = self._request("PUT", path, data=data)
        return resp.json() if resp.text else {}

    def delete(self, path: str, data: dict | None = None) -> None:
        self._request("DELETE", path, data=data)

    # ---- pagination ----

    def paged_get(self, path: str, params: dict | None = None,
                  max_pages: int | None = None):
        """Yield every item across pages, following the Link rel="next" header.

        Stops when there is no next link or a page comes back empty. The empty
        page check matters for System Log polling requests, where Okta always
        sends a next link. Raises OktaError after max_pages pages.
        """
        params = dict(params or {})
        params.setdefault("limit", 200)
        max_pages = max_pages or self.max_pages
        resp = self._request("GET", path, params=params)
        pages = 1
        while True:
            items = resp.json() if resp.text else []
            if isinstance(items, dict):  # a few endpoints wrap the list
                items = items.get("value", [])
            yield from items
            next_url = resp.links.get("next", {}).get("url")
            if not next_url or not items:
                return
            if pages >= max_pages:
                raise OktaError(f"Stopped paging {path} after {max_pages} pages.")
            # The next link already carries every query parameter; pass it as-is.
            resp = self._request("GET", next_url)
            pages += 1

    # ---- System Log ----

    def list_logs(self, filter: str | None = None, since: str | None = None,
                  until: str | None = None):
        """Bounded System Log read: events published between since and until.

        until defaults to now. With both bounds set Okta returns a finite set
        of pages. Without until, an ascending query is a polling query whose
        next link never goes away.
        """
        params = {"sortOrder": "ASCENDING", "limit": 1000,
                  "until": until or utc_now_iso()}
        if filter:
            params["filter"] = filter
        if since:
            params["since"] = since
        return self.paged_get("/api/v1/logs", params)

    def poll_logs(self, cursor: str | None, filter: str | None = None,
                  since: str | None = None) -> tuple[list, str]:
        """One polling pass for watch mode.

        Pass cursor=None the first time (with since/filter), then pass back the
        cursor this returns. Reads pages until an empty one, which is how Okta
        signals "caught up", and returns (events, cursor_for_next_poll).
        """
        if cursor is None:
            params = {"sortOrder": "ASCENDING", "limit": 1000}
            if filter:
                params["filter"] = filter
            if since:
                params["since"] = since
            resp = self._request("GET", "/api/v1/logs", params=params)
        else:
            resp = self._request("GET", cursor)
        events = []
        current = resp.url
        for _ in range(self.max_pages):
            page = resp.json() if resp.text else []
            next_url = resp.links.get("next", {}).get("url")
            events.extend(page)
            if not page or not next_url:
                # Resume from the empty page's next link when there is one.
                return events, next_url or current
            current = next_url
            resp = self._request("GET", next_url)
        raise OktaError("System Log polling did not catch up; giving up.")

    # ---- convenience wrappers ----

    def list_users(self, status: str | list[str] | None = "ACTIVE"):
        params = {}
        statuses = [status] if isinstance(status, str) else list(status or [])
        if statuses:
            params["filter"] = " or ".join(
                f'status eq "{quote_filter_value(s)}"' for s in statuses)
        return self.paged_get("/api/v1/users", params)

    def get_user_by_login(self, login: str) -> dict | None:
        """Return the user with this exact login, or None."""
        flt = f'profile.login eq "{quote_filter_value(login)}"'
        for u in self.paged_get("/api/v1/users", {"filter": flt, "limit": 2}):
            return u
        return None

    def get_current_user(self) -> dict | None:
        """The user an SSWS token belongs to (GET /api/v1/users/me).

        Returns None in OAuth mode, where there is no user behind the token.
        """
        if self.auth_mode != "ssws":
            return None
        return self.get("/api/v1/users/me")

    def list_factors(self, user_id: str) -> list:
        return list(self.paged_get(f"/api/v1/users/{user_id}/factors"))

    def list_user_groups(self, user_id: str):
        return self.paged_get(f"/api/v1/users/{user_id}/groups")

    def list_policies(self, policy_type: str):
        return self.paged_get("/api/v1/policies", {"type": policy_type})

    def list_policy_rules(self, policy_id: str):
        return self.paged_get(f"/api/v1/policies/{policy_id}/rules")

    def list_zones(self):
        return self.paged_get("/api/v1/zones")

    def list_apps(self):
        return self.paged_get("/api/v1/apps")

    def list_app_users(self, app_id: str):
        return self.paged_get(f"/api/v1/apps/{app_id}/users")

    def list_groups(self, query: str | None = None):
        params = {}
        if query:
            params["q"] = query
        return self.paged_get("/api/v1/groups", params)

    def list_group_members(self, group_id: str):
        return self.paged_get(f"/api/v1/groups/{group_id}/users")

    def list_user_roles(self, user_id: str):
        return self.paged_get(f"/api/v1/users/{user_id}/roles")

    def list_group_roles(self, group_id: str):
        return self.paged_get(f"/api/v1/groups/{group_id}/roles")

    def list_role_assignee_user_ids(self) -> list[str]:
        """IDs of every user holding an admin role, directly or through a group.

        GET /api/v1/iam/assignees/users returns {"value": [...], "_links": {...}}
        rather than a bare array, so it pages through _links.next.
        """
        ids, url, pages = [], "/api/v1/iam/assignees/users", 0
        params = {"limit": 100}
        while url and pages < self.max_pages:
            body = self._request("GET", url, params=params).json() or {}
            params = None
            pages += 1
            ids.extend(u["id"] for u in body.get("value", []) if u.get("id"))
            url = (((body.get("_links") or {}).get("next") or {}).get("href"))
            if not body.get("value"):
                break
        return ids

    def list_api_tokens(self):
        return self.paged_get("/api/v1/api-tokens")

    def list_auth_servers(self):
        return self.paged_get("/api/v1/authorizationServers")


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
