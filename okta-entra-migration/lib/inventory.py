"""Shared contract helpers: load/save the toolkit's JSON inventory shape.

Contract (produced by export_inventory.py, consumed by all other scripts):

    {
      "exportedAt": "2026-09-29T00:00:00Z",
      "source": {"oktaDomain": "https://example.okta.com", "live": false},
      "users": [
        {"id": "00u1", "login": "ada@example.com", "email": "ada@example.com",
         "firstName": "Ada", "lastName": "Lovelace", "status": "ACTIVE",
         "userType": "USER", "credentialProvider": "OKTA",
         "groups": ["00g1"], "apps": ["0oa1"],
         "profile": {...raw Okta profile...}}
      ],
      "groups": [
        {"id": "00g1", "name": "Engineering", "description": "...",
         "type": "OKTA_GROUP", "members": ["00u1"], "assignedApps": ["0oa1"],
         "dynamicRule": "user.department == \"Engineering\"", "dynamicRuleStatus": "ACTIVE"}
      ],
      "apps": [
        {"id": "0oa1", "name": "slack", "label": "Slack",
         "status": "ACTIVE", "signOnMode": "SAML_2_0",
         "sso": {"issuer": "http://www.okta.com/abc123",
                 "ssoUrl": "https://example.okta.com/app/slack/abc123/sso/saml",
                 "audience": "https://slack.com"},
         "assignedGroups": ["00g1"], "assignedUsers": ["00u1"],
         "owner": "it@example.com"}
      ],
      "policies": [{"id": "00p1", "name": "...", "type": "OKTA_SIGN_ON",
                    "status": "ACTIVE", "rules": [...]}],
      "apiTokens": [{"id": "tok1", "name": "ci-deploy", "clientName": "...",
                     "created": "...", "lastUpdated": "...", "expiresAt": null}],
      "oauthApps": [{"id": "0oa2", "name": "report-bot", "label": "Report Bot",
                     "clientId": "0oab...", "grantTypes": ["client_credentials"],
                     "redirectUris": [], "scopes": ["okta.users.read"]}]
    }

Service-account users are regular "users" entries with userType == "SERVICE"
or a login starting with "svc_"; inventory_service_accounts.py keys off that.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from secure_io import atomic_write_text

INVENTORY_KEYS = (
    "exportedAt", "source", "users", "groups", "apps",
    "policies", "apiTokens", "oauthApps",
)


def new_inventory(source: dict | None = None) -> dict:
    inv = {k: [] for k in INVENTORY_KEYS if k not in ("exportedAt", "source")}
    inv["exportedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inv["source"] = source or {"live": False}
    return inv


def load_inventory(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        inv = json.load(fh)
    for key in ("users", "groups", "apps", "policies", "apiTokens", "oauthApps"):
        inv.setdefault(key, [])
    inv.setdefault("source", {})
    return inv


def save_inventory(inv: dict, path: str) -> None:
    # 0600 + atomic: inventories carry user lists, group memberships and
    # tenant structure -- never world-readable, never half-written.
    atomic_write_text(path,
                      json.dumps(inv, indent=2, sort_keys=False) + "\n",
                      mode=0o600)


def by_id(items: list[dict], key: str = "id") -> dict:
    return {it.get(key): it for it in items if it.get(key)}
