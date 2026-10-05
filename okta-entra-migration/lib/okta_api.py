"""Okta Management API client.

Auth comes from environment variables only -- never hardcoded, never prompted:

    OKTA_DOMAIN        e.g. https://example.okta.com
    OKTA_API_TOKEN     an SSWS API token, minted by an Okta admin account
                       holding a read-only admin role (least privilege:
                       "Read-Only Administrator" covers every endpoint this
                       toolkit pages).

OAuth client-credentials is deliberately NOT offered: Okta's Org
Authorization Server requires ``private_key_jwt`` client authentication
for service apps (Okta support article "Client Credentials Requests to
the Org Authorization Server Must Use Private Key JWT"), and this
toolkit avoids that key-management burden. If your org policy forbids
SSWS tokens, OAuth support is a future enhancement -- not this version.

Conventions: cursor pagination via the RFC5988 Link header, `limit`
default 200, 429 handling that honors `x-rate-limit-reset`, and AuthError
on 401/403.
"""

from __future__ import annotations

import os
import time
import urllib.parse

import requests

from http_retry import okta_reset_wait_seconds

DEFAULT_TIMEOUT = 30
USER_AGENT = "okta-entra-toolkit/0.1"

class OktaAuthError(RuntimeError):
    """Raised when credentials are missing or rejected."""


class OrgMismatchError(RuntimeError):
    """Raised when the connected Okta org is not the configured domain."""


class OktaClient:
    def __init__(self, domain: str | None = None,
                 api_token: str | None = None):
        domain = (domain or os.environ.get("OKTA_DOMAIN") or "").rstrip("/")
        token = api_token or os.environ.get("OKTA_API_TOKEN")
        if not domain:
            raise OktaAuthError(
                "Set OKTA_DOMAIN (e.g. https://example.okta.com).")
        if not domain.startswith("http"):
            domain = "https://" + domain
        if not token:
            raise OktaAuthError(
                "Set OKTA_API_TOKEN (SSWS). Mint it in the Okta Admin "
                "Console under Security > API > Tokens, from an admin "
                "account with a read-only admin role.")
        self.base_url = domain
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Authorization": f"SSWS {token}",
        })
        self.auth_mode = "ssws"

    def _request(self, method: str, path: str, params: dict | None = None,
                 data: dict | None = None, retries: int = 5):
        for attempt in range(retries):
            resp = self.session.request(method, self.base_url + path,
                                        params=params, json=data,
                                        timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                # x-rate-limit-reset is UTC epoch seconds: sleep until the
                # window resets (plus jitter), with backoff fallback.
                time.sleep(okta_reset_wait_seconds(
                    resp.headers.get("x-rate-limit-reset"), attempt))
                continue
            if resp.status_code in (401, 403):
                raise OktaAuthError(
                    f"Okta rejected the API token (HTTP {resp.status_code}). "
                    "Check OKTA_API_TOKEN and the token's admin role.")
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

    # ---- convenience wrappers used by the export scripts ----

    def verify_org(self) -> dict:
        """Confirm the connected org matches OKTA_DOMAIN.

        Returns the /api/v1/org record. Raises OrgMismatchError if the
        org's canonical domain differs from the configured OKTA_DOMAIN --
        the classic "right token, wrong tenant" mistake. (Custom-domain
        setups: point OKTA_DOMAIN at the *.okta.com domain.)
        """
        org = self._request("GET", "/api/v1/org").json()
        expected = urllib.parse.urlparse(self.base_url).hostname or ""
        actual = (org.get("subdomain") or "") + ".okta.com"
        if expected.lower() != actual.lower():
            raise OrgMismatchError(
                f"Connected Okta org {actual} does not match "
                f"OKTA_DOMAIN={expected}. Refusing to continue -- check "
                f"your domain and token before retrying.")
        return org

    def list_users(self):
        return self.paged_get("/api/v1/users")

    def list_groups(self):
        return self.paged_get("/api/v1/groups", {"expand": "stats"})

    def list_group_members(self, group_id: str):
        return self.paged_get(f"/api/v1/groups/{group_id}/users")

    def list_apps(self):
        return self.paged_get("/api/v1/apps")

    def list_app_users(self, app_id: str):
        return self.paged_get(f"/api/v1/apps/{app_id}/users")

    def list_app_groups(self, app_id: str):
        return self.paged_get(f"/api/v1/apps/{app_id}/groups")

    def list_policies(self, policy_type: str):
        return self.paged_get("/api/v1/policies", {"type": policy_type})

    def list_policy_rules(self, policy_id: str):
        return self.paged_get(f"/api/v1/policies/{policy_id}/rules")

    def list_api_tokens(self):
        return self.paged_get("/api/v1/api/tokens")
