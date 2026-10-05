"""Shared Okta API client.

Auth comes from environment variables only -- never hardcode a token:

    OKTA_DOMAIN      e.g. https://dev-123456.okta.com
    OKTA_API_TOKEN   an SSWS API token (read-only is enough for auditors)
"""

from __future__ import annotations

import os
import time
import urllib.parse

import requests

DEFAULT_TIMEOUT = 30


class OktaAuthError(RuntimeError):
    """Raised when credentials are missing or rejected."""


class OktaClient:
    def __init__(self, domain: str | None = None, api_token: str | None = None):
        domain = (domain or os.environ.get("OKTA_DOMAIN") or "").rstrip("/")
        token = api_token or os.environ.get("OKTA_API_TOKEN")
        if not domain or not token:
            raise OktaAuthError(
                "Set OKTA_DOMAIN (e.g. https://dev-123456.okta.com) and "
                "OKTA_API_TOKEN environment variables."
            )
        if not domain.startswith("http"):
            domain = "https://" + domain
        self.base_url = domain
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "okta-ideas/0.1",
        })

    def _request(self, method: str, path: str, params: dict | None = None,
                 data: dict | None = None, retries: int = 5):
        for _ in range(retries):
            resp = self.session.request(method, self.base_url + path,
                                        params=params, json=data,
                                        timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                # Honor Okta's rate-limit reset header, then retry.
                wait = int(resp.headers.get("x-rate-limit-reset", "5"))
                time.sleep(max(1, min(wait, 60)) + 1)
                continue
            if resp.status_code in (401, 403):
                raise OktaAuthError(
                    f"Okta rejected the API token (HTTP {resp.status_code}). "
                    "Check OKTA_API_TOKEN and its permissions."
                )
            resp.raise_for_status()
            return resp
        raise RuntimeError("Okta rate limit persisted after retries; try again later.")

    def paged_get(self, path: str, params: dict | None = None):
        """Yield items across all pages (Okta `after` cursor via Link header)."""
        params = dict(params or {})
        params.setdefault("limit", 200)
        next_url = self.base_url + path
        first = True
        while next_url:
            if first:
                resp = self._request("GET", path, params=params)
                first = False
            else:
                # Follow-up URLs already carry their query string.
                parsed = urllib.parse.urlparse(next_url)
                resp = self._request(
                    "GET", parsed.path,
                    params=dict(urllib.parse.parse_qsl(parsed.query)))
            for item in resp.json():
                yield item
            next_url = resp.links.get("next", {}).get("url")

    # ---- write verbs (for provisioning kits; always gated behind explicit
    # --apply / --confirm flags in the scripts that use them) ----

    def post(self, path: str, data: dict | None = None) -> dict:
        resp = self._request("POST", path, data=data)
        return resp.json() if resp.text else {}

    def put(self, path: str, data: dict | None = None) -> dict:
        resp = self._request("PUT", path, data=data)
        return resp.json() if resp.text else {}

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    # ---- convenience wrappers ----

    def list_users(self, status: str = "ACTIVE"):
        params = {}
        if status:
            params["filter"] = f'status eq "{status}"'
        return self.paged_get("/api/v1/users", params)

    def get_user_by_login(self, login: str) -> dict | None:
        """Return the first user matching a login, or None."""
        for u in self.paged_get("/api/v1/users",
                                {"filter": f'profile.login eq "{login}"', "limit": 2}):
            return u
        return None

    def list_factors(self, user_id: str) -> list:
        return list(self.paged_get(f"/api/v1/users/{user_id}/factors"))

    def list_logs(self, filter: str | None = None, since: str | None = None):
        """Iterate System Log events. `since` is an ISO8601 UTC timestamp."""
        params = {}
        if filter:
            params["filter"] = filter
        if since:
            params["since"] = since
        params["sortOrder"] = "ASCENDING"
        return self.paged_get("/api/v1/logs", params)

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

    def list_roles(self):
        return self.paged_get("/api/v1/roles")

    def list_user_roles(self, user_id: str):
        return self.paged_get(f"/api/v1/users/{user_id}/roles")

    def list_group_roles(self, group_id: str):
        return self.paged_get(f"/api/v1/groups/{group_id}/roles")

    def list_auth_servers(self):
        return self.paged_get("/api/v1/authorizationServers")
