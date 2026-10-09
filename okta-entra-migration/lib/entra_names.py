"""Entra naming rules: UPN characters and mailNickname sanitizing.

Sources (Microsoft Learn, checked 2026-10-09):

* Create user (graph/api/user-post-users): userPrincipalName "cannot contain
  accent characters. Only the following characters are allowed A - Z, a - z,
  0 - 9, ' . - _ ! # ^ ~", and the domain must be a verified domain.
* Create group (graph/api/group-post-groups): mailNickname is required,
  max 64 characters, ASCII 0-127 only, excluding @ () \\ [] " ; : <> ,
  and space.

For mailNickname we keep to the narrower UPN-safe set for both users and
groups, so one sanitizer covers both and the result is always accepted.
"""

from __future__ import annotations

import hashlib
import re

UPN_LOCAL_RE = re.compile(r"^[A-Za-z0-9'.\-_!#^~]+$")
_NICK_BAD = re.compile(r"[^A-Za-z0-9'.\-_!#^~]+")
MAIL_NICKNAME_MAX = 64


def upn_problem(upn: str) -> str | None:
    """Return why *upn* can't be used as an Entra UPN, or None if it can."""
    if not upn or upn.count("@") != 1:
        return "UPN must have exactly one '@'"
    local, domain = upn.split("@")
    if not local or not domain:
        return "UPN has an empty local part or domain"
    if not UPN_LOCAL_RE.match(local):
        bad = sorted(set(_NICK_BAD.findall(local)))
        return (f"UPN local part contains characters Entra does not allow "
                f"({''.join(bad)!r}); allowed: A-Z a-z 0-9 ' . - _ ! # ^ ~")
    if local.startswith(".") or local.endswith("."):
        return "UPN local part can't start or end with '.'"
    return None


def mail_nickname(source: str, unique_key: str | None = None) -> str:
    """Build a mailNickname Entra will accept from *source*.

    Disallowed characters (including '+', spaces and accents) become '-'.
    When *unique_key* is given, a short hash of it is appended so two
    groups with similar names can't collide.
    """
    base = _NICK_BAD.sub("-", (source or "").strip()).strip(".-")
    base = re.sub(r"-{2,}", "-", base)
    suffix = ""
    if unique_key:
        suffix = "-" + hashlib.sha256(unique_key.encode()).hexdigest()[:8]
    if not base:
        base = "migrated"
    return base[:MAIL_NICKNAME_MAX - len(suffix)].rstrip(".-") + suffix
