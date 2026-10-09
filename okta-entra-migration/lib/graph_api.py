"""Microsoft Graph client for the Entra side of the migration.

Auth comes from environment variables only -- never hardcoded, never prompted:

    GRAPH_TENANT_ID
    GRAPH_CLIENT_ID
    GRAPH_CLIENT_SECRET   (client-credentials flow)

Application permissions each script needs are listed in the README.

Only used behind explicit ``--live`` flags; every script works offline
against local JSON fixtures by default.
"""

from __future__ import annotations

import os
import time

import requests

from http_retry import retry_after_seconds

DEFAULT_TIMEOUT = 30
USER_AGENT = "okta-entra-toolkit/0.2"
LOGIN_HOST = "https://login.microsoftonline.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RETRYABLE_5XX = (500, 502, 503, 504)

# Learn, "Add members": PATCH /groups/{id} with members@odata.bind accepts
# at most 20 members per request.
MAX_MEMBERS_PER_PATCH = 20


class GraphAuthError(RuntimeError):
    """Raised when Graph credentials are missing or rejected."""


class TenantMismatchError(RuntimeError):
    """Raised when the connected Entra tenant is not the expected one."""


class GraphClient:
    def __init__(self, tenant_id: str | None = None,
                 client_id: str | None = None,
                 client_secret: str | None = None,
                 session=None, sleep=time.sleep):
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
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        })
        self.base_url = GRAPH_BASE
        self._mint_token()

    def _mint_token(self) -> None:
        """(Re)fetch a client-credentials access token into the session."""
        resp = self.session.post(
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
        # `path` may be an absolute @odata.nextLink URL; those get the same
        # retry and backoff treatment as everything else.
        url = path if path.startswith("http") else self.base_url + path
        reminted = False
        for attempt in range(retries):
            resp = self.session.request(method, url, params=params, json=data,
                                        timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                self._sleep(retry_after_seconds(
                    resp.headers.get("Retry-After"), attempt, cap=300.0))
                continue
            if resp.status_code in RETRYABLE_5XX and method == "GET" \
                    and attempt < retries - 1:
                self._sleep(retry_after_seconds(
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
            if resp.status_code >= 400:
                raise GraphRequestError(method, path, resp)
            return resp
        raise RuntimeError(f"Graph kept throttling or failing {path} after "
                           f"{retries} attempts; try again later.")

    def paged_get(self, path: str, params: dict | None = None,
                  select: str | None = None):
        """Yield items across all pages (@odata.nextLink)."""
        params = dict(params or {})
        if select:
            params["$select"] = select
        resp = self._request("GET", path, params=params)
        while True:
            body = resp.json()
            yield from body.get("value", [])
            next_url = body.get("@odata.nextLink")
            if not next_url:
                return
            resp = self._request("GET", next_url)

    # ---- reads ----

    def verify_tenant(self) -> dict:
        """Read /organization and compare it with GRAPH_TENANT_ID.

        The token is minted for GRAPH_TENANT_ID, so this mostly catches a
        domain name or typo in that variable. The check that protects you
        from running against the wrong environment is the operator-supplied
        ``--expect-tenant`` (see tenant_guard.check_graph_tenant).
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
                            "displayName,accountEnabled,jobTitle,department,"
                            "userType")

    def list_user_anchors(self):
        """Users with their onPremisesImmutableId (for ImmutableID checks)."""
        return self.paged_get(
            "/users", select="id,userPrincipalName,mail,userType,"
                            "onPremisesImmutableId")

    def list_domains(self):
        return self.paged_get("/domains",
                              select="id,isVerified,authenticationType")

    def list_groups(self):
        return self.paged_get(
            "/groups", select="id,displayName,description,mailEnabled,"
                             "mailNickname,securityEnabled,groupTypes,"
                             "membershipRule")

    def list_group_member_ids(self, group_id: str) -> set[str]:
        return {m.get("id") for m in self.paged_get(
            f"/groups/{group_id}/members", select="id") if m.get("id")}

    # ---- writes (only called behind explicit --apply flags) ----

    def create_user(self, body: dict) -> dict:
        created = self._request("POST", "/users", data=body).json()
        if not created.get("id"):
            raise RuntimeError("Graph returned no id for the created user")
        return created

    def create_group(self, body: dict) -> dict:
        created = self._request("POST", "/groups", data=body).json()
        if not created.get("id"):
            raise RuntimeError("Graph returned no id for the created group")
        return created

    def add_group_members(self, group_id: str, member_ids: list[str]) -> None:
        """Add up to 20 directory objects to a group in one PATCH.

        Learn: if any reference in the body is bad (including one that is
        already a member), none of them are added. Callers should diff
        against the current membership first.
        """
        if len(member_ids) > MAX_MEMBERS_PER_PATCH:
            raise ValueError(f"at most {MAX_MEMBERS_PER_PATCH} members per call")
        body = {"members@odata.bind": [
            f"{GRAPH_BASE}/directoryObjects/{mid}" for mid in member_ids]}
        self._request("PATCH", f"/groups/{group_id}", data=body)

    def add_group_member(self, group_id: str, member_id: str) -> None:
        self._request("POST", f"/groups/{group_id}/members/$ref",
                      data={"@odata.id":
                            f"{GRAPH_BASE}/directoryObjects/{member_id}"})

    def create_temporary_access_pass(self, user_id: str,
                                     lifetime_minutes: int = 480) -> dict:
        """Create a single-use Temporary Access Pass for first sign-in.

        The returned dict includes ``temporaryAccessPass`` (the secret).
        Callers must write it only to an explicitly requested 0600 file or
        show it on an explicitly requested terminal, never into a report.
        The TAP authentication-method policy must be enabled in the tenant,
        and the lifetime must fit inside that policy.
        """
        body = {"lifetimeInMinutes": lifetime_minutes, "isUsableOnce": True}
        return self._request(
            "POST",
            f"/users/{user_id}/authentication/temporaryAccessPassMethods",
            data=body).json()


class GraphRequestError(RuntimeError):
    """A Graph call returned 4xx/5xx. Carries the status and Graph's message."""

    def __init__(self, method: str, path: str, resp):
        self.status_code = resp.status_code
        try:
            err = (resp.json() or {}).get("error") or {}
            message = err.get("message") or ""
            code = err.get("code") or ""
        except ValueError:
            message, code = (resp.text or "")[:200], ""
        self.code = code
        self.graph_message = message
        super().__init__(f"{method} {path} -> HTTP {resp.status_code} "
                         f"{code}: {message}".strip())
