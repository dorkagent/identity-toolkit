"""Wrong-tenant protection and the --apply confirmation, shared by --live scripts.

What actually protects you here is ``--expect-tenant``: the operator states
which Entra tenant (by GUID) the run is meant for, and the run stops if the
credentials in the environment belong to a different one. Without it, the
only check is that /organization agrees with GRAPH_TENANT_ID, which is the
tenant the token was minted for anyway. Scripts that write to Entra require
``--expect-tenant`` for ``--apply``.
"""

from __future__ import annotations

import re
import sys

GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_guid(value: str | None) -> bool:
    return bool(value) and bool(GUID_RE.match(value.strip()))


def check_graph_tenant(gc, log=print, expect_tenant: str | None = None):
    """Verify the Graph client is talking to the tenant the operator expects.

    Prints the connected tenant and returns its /organization record, or
    prints an error and returns None on any mismatch.
    """
    from graph_api import TenantMismatchError
    try:
        org = gc.verify_tenant()
    except TenantMismatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return None
    actual = (org.get("id") or "").lower()
    if expect_tenant is not None:
        if not is_guid(expect_tenant):
            print(f"error: --expect-tenant must be the tenant GUID, got "
                  f"{expect_tenant!r}", file=sys.stderr)
            return None
        if actual != expect_tenant.strip().lower():
            print(f"error: connected Entra tenant {actual or '?'} "
                  f"({org.get('displayName') or '?'}) is not the expected "
                  f"tenant {expect_tenant}. Refusing to continue.",
                  file=sys.stderr)
            return None
    log(f"connected Entra tenant: {org.get('displayName') or '?'} "
        f"({org.get('id') or '?'})")
    return org


def check_okta_org(client, log=print):
    """Verify the Okta client is talking to the configured org."""
    from okta_api import OrgMismatchError
    try:
        org = client.verify_org()
    except OrgMismatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return None
    log(f"connected Okta org: {org.get('subdomain') or '?'} "
        f"(id {org.get('id') or '?'})")
    return org


def confirm_apply(summary: str, yes: bool) -> bool:
    """Ask the operator to type APPLY before a mutating run.

    Returns True when confirmed (or --yes). Refuses, without prompting,
    when stdin is not a TTY and --yes was not given, so automation can't
    hang waiting for input.
    """
    if yes:
        return True
    if not sys.stdin.isatty():
        print("error: refusing --apply without confirmation: stdin is not "
              "a TTY and --yes was not given", file=sys.stderr)
        return False
    print(summary)
    try:
        answer = input("Type APPLY to proceed (anything else aborts): ")
    except EOFError:
        return False
    return answer.strip() == "APPLY"
