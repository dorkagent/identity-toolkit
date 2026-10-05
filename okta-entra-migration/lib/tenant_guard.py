"""Wrong-tenant protection and --apply confirmation, shared by --live scripts.

Every live run prints the connected tenant/org *before* doing anything, and
aborts cleanly (exit 2, no traceback) if the connected tenant is not the
configured one. Mutating runs (--apply) additionally require the operator
to type APPLY, unless --yes is given for automation.
"""

from __future__ import annotations

import sys


def check_graph_tenant(gc, log=print) -> dict:
    """Verify the Graph client is talking to the configured tenant.

    Prints the connected tenant and returns its /organization record.
    Returns None and prints an error if the tenant mismatches.
    """
    from graph_api import TenantMismatchError
    try:
        org = gc.verify_tenant()
    except TenantMismatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return None
    log(f"connected Entra tenant: {org.get('displayName') or '?'} "
        f"({org.get('id') or '?'})")
    return org


def check_okta_org(client, log=print) -> dict:
    """Verify the Okta client is talking to the configured org domain."""
    from okta_api import OrgMismatchError
    try:
        org = client.verify_org()
    except OrgMismatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return None
    log(f"connected Okta org: {(org.get('subdomain') or '?')}.okta.com")
    return org


def confirm_apply(summary: str, yes: bool) -> bool:
    """Ask the operator to type APPLY before a mutating run.

    Returns True when confirmed (or --yes). Refuses -- without prompting --
    when stdin is not a TTY and --yes was not given, so automation cannot
    accidentally hang waiting for input.
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
