"""Load/save helpers for the kit's JSON inventory ("the contract").

export_inventory.py writes it; every other script reads it. The README has
an annotated example. Top-level keys:

    exportedAt, source        when and where the export came from
    users                     one entry per Okta user, DEPROVISIONED included
    groups                    groups with member ids, assigned apps, and the
                              ids of the group rules that target them
    groupRules                Okta group rules (expression, status, target
                              group ids, exclusions)
    apps                      apps with SAML/OIDC settings and assignments
    policies                  policies of every type the org supports, with rules
    apiTokens, oauthApps      non-human credentials
    exportErrors              {section: message} for anything the export
                              couldn't read; empty when the export is complete

Service-account users are regular "users" entries with userType == "SERVICE"
or a login starting with "svc_"; inventory_service_accounts.py keys off that.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from secure_io import atomic_write_text

INVENTORY_KEYS = (
    "exportedAt", "source", "users", "groups", "apps",
    "policies", "apiTokens", "oauthApps", "groupRules", "exportErrors",
)
LIST_KEYS = ("users", "groups", "apps", "policies", "apiTokens", "oauthApps",
             "groupRules")


def new_inventory(source: dict | None = None) -> dict:
    inv = {k: [] for k in LIST_KEYS}
    inv["exportErrors"] = {}
    inv["exportedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inv["source"] = source or {"live": False}
    return inv


def load_inventory(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        inv = json.load(fh)
    for key in LIST_KEYS:
        inv.setdefault(key, [])
    inv.setdefault("exportErrors", {})
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
