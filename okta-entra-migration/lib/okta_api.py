"""Okta Management API client (read-only use).

Auth comes from environment variables only -- never hardcoded, never prompted:

    OKTA_DOMAIN          e.g. https://example.okta.com
    OKTA_API_TOKEN       an SSWS API token. Mint it from an admin account with
                         a read-only admin role.
    OKTA_EXPECT_ORG_ID   optional. The org id (``00o...``) you expect. Needed
                         when OKTA_DOMAIN is a custom URL domain, because the
                         org's subdomain can't be checked against it.

Why SSWS and not OAuth: Okta recommends scoped OAuth 2.0 service apps over
SSWS tokens, and that is the better long-term setup. Service apps must
authenticate with ``private_key_jwt``, which means managing a key pair. This
kit keeps the setup to one token for now; OAuth support is on the list.

Conventions: cursor pagination via the Link header, ``limit`` 200,
429 handling that honours ``x-rate-limit-reset`` (UTC epoch seconds), a few
retries on 5xx for GETs, and ``OktaAuthError`` on 401/403.
"""

from __future__ import annotations

import os
import time
import urllib.parse

import requests

from http_retry import okta_reset_wait_seconds, retry_after_seconds

DEFAULT_TIMEOUT = 30
USER_AGENT = "okta-entra-toolkit/0.2"
RETRYABLE_5XX = (500, 502, 503, 504)


class OktaAuthError(RuntimeError):
    """Raised when credentials are missing or rejected (401/403)."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class OrgMismatchError(RuntimeError):
    """Raised when the connected Okta org is not the configured one."""


class OktaClient:
    def __init__(self, domain: str | None = None,
                 api_token: str | None = None,
                 expect_org_id: str | None = None,
                 session=None, sleep=time.sleep):
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
        self.expect_org_id = expect_org_id or os.environ.get("OKTA_EXPECT_ORG_ID")
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Authorization": f"SSWS {token}",
        })
        self.auth_mode = "ssws"
        self._sleep = sleep

    def _request(self, method: str, path: str, params: dict | None = None,
                 data: dict | None = None, retries: int = 5):
        url = path if path.startswith("http") else self.base_url + path
        for attempt in range(retries):
            try:
                resp = self.session.request(method, url, params=params,
                                            json=data, timeout=DEFAULT_TIMEOUT)
            except requests.ConnectionError:
                if method != "GET" or attempt == retries - 1:
                    raise
                self._sleep(retry_after_seconds(None, attempt))
                continue
            if resp.status_code == 429:
                self._sleep(okta_reset_wait_seconds(
                    resp.headers.get("x-rate-limit-reset"), attempt))
                continue
            if resp.status_code in RETRYABLE_5XX and method == "GET" \
                    and attempt < retries - 1:
                self._sleep(retry_after_seconds(None, attempt))
                continue
            if resp.status_code in (401, 403):
                raise OktaAuthError(
                    f"Okta rejected the request to {path} "
                    f"(HTTP {resp.status_code}). Check OKTA_API_TOKEN and "
                    f"the admin role behind it.", resp.status_code)
            resp.raise_for_status()
            return resp
        raise RuntimeError(f"Okta kept rate-limiting or failing {path} "
                           f"after {retries} attempts; try again later.")

    def paged_get(self, path: str, params: dict | None = None):
        """Yield items across all pages.

        The first request carries ``params``; after that the ``next`` link
        from the Link header is followed exactly as Okta returned it.
        """
        params = dict(params or {})
        params.setdefault("limit", 200)
        resp = self._request("GET", path, params=params)
        while True:
            yield from resp.json()
            next_url = resp.links.get("next", {}).get("url")
            if not next_url:
                return
            resp = self._request("GET", next_url)

    # ---- org check ----

    def verify_org(self) -> dict:
        """Confirm the token belongs to the org OKTA_DOMAIN points at.

        Returns the /api/v1/org record. The first label of the configured
        host must equal the org's ``subdomain`` (works for okta.com,
        oktapreview.com, okta-emea.com and other Okta cells). For a custom
        URL domain that check can't work, so OKTA_EXPECT_ORG_ID (or
        ``expect_org_id``) must match the org's ``id`` instead.
        """
        org = self._request("GET", "/api/v1/org").json()
        host = (urllib.parse.urlparse(self.base_url).hostname or "").lower()
        subdomain = (org.get("subdomain") or "").lower()
        org_id = org.get("id") or ""
        expect = getattr(self, "expect_org_id", None)
        if expect:
            if org_id != expect:
                raise OrgMismatchError(
                    f"Connected Okta org id {org_id or '?'} does not match "
                    f"the expected org id {expect}. Refusing to "
                    f"continue.")
            return org
        if not subdomain or host.split(".")[0] != subdomain:
            raise OrgMismatchError(
                f"Connected Okta org (subdomain {subdomain or '?'}, id "
                f"{org_id or '?'}) does not match OKTA_DOMAIN={host}. If "
                f"you use a custom URL domain, set OKTA_EXPECT_ORG_ID to the "
                f"org id instead. Refusing to continue.")
        return org

    # ---- read wrappers used by the exporter ----

    def list_users(self):
        """All users, including DEPROVISIONED ones.

        ``GET /api/v1/users`` without a filter omits DEPROVISIONED users
        (per the API reference), so a second ``search`` query fetches them.
        """
        seen = set()
        for u in self.paged_get("/api/v1/users"):
            seen.add(u.get("id"))
            yield u
        for u in self.paged_get("/api/v1/users",
                                {"search": 'status eq "DEPROVISIONED"'}):
            if u.get("id") not in seen:
                yield u

    def list_groups(self):
        return self.paged_get("/api/v1/groups")

    def list_group_rules(self):
        return self.paged_get("/api/v1/groups/rules")

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
        return self.paged_get("/api/v1/api-tokens")
