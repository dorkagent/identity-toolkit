"""Microsoft Graph client (Entra ID reads/writes).

Auth comes from environment variables only -- never hardcoded, never prompted:

    GRAPH_TENANT_ID
    GRAPH_CLIENT_ID
    GRAPH_CLIENT_SECRET   (client-credentials flow; app needs Graph
                           application permissions, e.g. User.Read.All,
                           Group.ReadWrite.All, Application.ReadWrite.All)

Only used behind explicit `--live` flags; every script defaults to working
offline against local JSON fixtures.
"""

from __future__ import annotations

import os
import time

import requests

from http_retry import retry_after_seconds

DEFAULT_TIMEOUT = 30
USER_AGENT = "okta-entra-toolkit/0.1"
LOGIN_HOST = "https://login.microsoftonline.com"


class GraphAuthError(RuntimeError):
    """Raised when Graph credentials are missing or rejected."""


class TenantMismatchError(RuntimeError):
    """Raised when the connected Entra tenant is not the configured one."""


class GraphClient:
    def __init__(self, tenant_id: str | None = None,
                 client_id: str | None = None,
                 client_secret: str | None = None):
        tenant_id = tenant_id or os.environ.get("GRAPH_TENANT_ID")
        client_id = client_id or os.environ.get("GRAPH_CLIENT_ID")
        client_secret = client_secret or os.environ.get("GRAPH_CLIENT_SECRET")
        if not (tenant_id and client_id and client_secret):
            raise GraphAuthError(
                "Set GRAPH_TENANT_ID, GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET "
                "(client-credentials flow).")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        })
        self._mint_token()
        self.base_url = "https://graph.microsoft.com/v1.0"

    def _mint_token(self) -> None:
        """(Re)fetch a client-credentials access token into the session."""
        resp = requests.post(
            f"{LOGIN_HOST}/{self._tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials",
                  "client_id": self._client_id,
                  "client_secret": self._client_secret,
                  "scope": "https://graph.microsoft.com/.default"},
            timeout=DEFAULT_TIMEOUT)
        if resp.status_code in (400, 401):
            raise GraphAuthError(
                f"Graph token request failed (HTTP {resp.status_code}): "
                f"{resp.text[:200]}")
        resp.raise_for_status()
        self.session.headers["Authorization"] = \
            f"Bearer {resp.json()['access_token']}"

    def _request(self, method: str, path: str, params: dict | None = None,
                 data: dict | None = None, retries: int = 5):
        # `path` may be an absolute @odata.nextLink URL -- pass those
        # through so every page gets the same retry/backoff treatment.
        url = path if path.startswith("http") else self.base_url + path
        reminted = False
        for attempt in range(retries):
            resp = self.session.request(method, url, params=params, json=data,
                                        timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                time.sleep(retry_after_seconds(
                    resp.headers.get("Retry-After"), attempt))
                continue
            if resp.status_code == 401 and not reminted:
                # Access token may have expired mid-run; mint once more.
                reminted = True
                self._mint_token()
                continue
            if resp.status_code == 401:
                raise GraphAuthError(
                    "Graph rejected the credentials (HTTP 401). Check "
                    "GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET and app permissions.")
            resp.raise_for_status()
            return resp
        raise RuntimeError("Graph rate limit persisted after retries; try again later.")

    def paged_get(self, path: str, params: dict | None = None, select: str | None = None):
        """Yield items across all pages (@odata.nextLink)."""
        params = dict(params or {})
        if select:
            params["$select"] = select
        next_url = self.base_url + path
        first = True
        while next_url:
            if first:
                resp = self._request("GET", path, params=params)
                first = False
            else:
                # nextLink is absolute; _request passes it through with
                # full retry/backoff handling (no bare session.get).
                resp = self._request("GET", next_url)
            body = resp.json()
            for item in body.get("value", []):
                yield item
            next_url = body.get("@odata.nextLink")

    # ---- reads used by the migration scripts ----

    def verify_tenant(self) -> dict:
        """Confirm the connected tenant matches GRAPH_TENANT_ID.

        Returns the /organization record (id, displayName). Raises
        TenantMismatchError if the ids differ -- the classic "right
        credentials, wrong tenant" mistake. Skips the comparison for the
        multi-tenant authorities ("common", "organizations") where no
        single expected tenant exists.
        """
        orgs = self._request(
            "GET", "/organization",
            params={"$select": "id,displayName"}).json()
        org = (orgs.get("value") or [{}])[0]
        expected = (self._tenant_id or "").lower()
        actual = (org.get("id") or "").lower()
        if expected not in ("", "common", "organizations") and actual != expected:
            raise TenantMismatchError(
                f"Connected Entra tenant {actual or '?'} "
                f"({org.get('displayName') or '?'}) does not match "
                f"GRAPH_TENANT_ID={self._tenant_id}. Refusing to continue -- "
                f"check your credentials before retrying.")
        return org

    def list_users(self):
        return self.paged_get(
            "/users", select="id,userPrincipalName,mail,givenName,surname,"
                            "displayName,accountEnabled,jobTitle,department")

    def list_user_anchors(self):
        """Users with their onPremisesImmutableId (for ImmutableID checks)."""
        return self.paged_get(
            "/users", select="id,userPrincipalName,mail,"
                            "onPremisesImmutableId")

    def list_domains(self):
        return self.paged_get("/domains", select="id,isVerified")

    def list_groups(self):
        return self.paged_get(
            "/groups", select="id,displayName,description,mailEnabled,"
                             "securityEnabled,groupTypes,membershipRule")

    def list_applications(self):
        return self.paged_get(
            "/applications",
            select="id,appId,displayName,signInAudience,web,"
                   "requiredResourceAccess")

    # ---- writes (only called behind explicit --apply flags) ----

    def create_user(self, body: dict) -> dict:
        return self._request("POST", "/users", data=body).json()

    def create_group(self, body: dict) -> dict:
        return self._request("POST", "/groups", data=body).json()

    def create_temporary_access_pass(self, user_id: str,
                                     lifetime_minutes: int = 480) -> dict:
        """Create a Temporary Access Pass for first-sign-in onboarding.

        This is the Microsoft-recommended credential for migration-created
        users: single-use, time-limited, and it satisfies MFA requirements
        on first use. The returned dict includes ``temporaryAccessPass``
        (the secret) -- callers must show it once / write it to an
        explicitly requested 0600 file, never bake it into a report.

        Requires the app registration to hold
        ``UserAuthenticationMethod.ReadWrite.All``.
        """
        body = {"lifetimeInMinutes": lifetime_minutes, "isUsableOnce": True}
        return self._request(
            "POST",
            f"/users/{user_id}/authentication/temporaryAccessPassMethods",
            data=body).json()
