"""Translate Okta group-rule expressions into Entra dynamic membership rules.

Okta side (Okta Expression Language reference, "Expressions in group
rules" and "Conditional expressions"): conditions combine with ``AND``,
``OR`` and ``!`` (``&&`` and ``||`` are accepted too), compare with ``==``
and ``!=``, and call ``String.stringContains(attr, "v")`` or
``String.startsWith(attr, "v")``. Strings use double or single quotes.

Entra side (Learn, "Manage rules for dynamic membership groups", checked
2026-10-09): logical operators are ``-and``, ``-or``, ``-not``; expression
operators include ``-eq``, ``-ne``, ``-contains``, ``-startsWith``; a
double quote inside a string value is escaped with a backtick; ``null``
is written unquoted; a rule body can be at most 3,072 characters.

Only the Okta forms above are translated, and only for Okta profile
attributes that map onto a user property Entra documents as usable in
dynamic rules. Everything else (``matches``, ``Arrays.contains``,
``isMemberOf*``, ``user.getInternalProperty``, custom attributes,
``costCenter``/``division``/``employeeType`` and so on) is reported as a
problem so a person can rewrite it. Nothing is guessed.

The parsed rule can also be *evaluated* against an Okta user profile with
Okta's semantics. mirror_groups.py uses that to spot members of a
rule-target group that the rules don't explain (direct assignments),
because an Entra dynamic group can't hold those.
"""

from __future__ import annotations

import re

# User string properties Entra documents for dynamic membership rules
# (Learn: groups-dynamic-membership, "Properties of type string").
ENTRA_DYNAMIC_USER_STRING_PROPS = frozenset({
    "city", "country", "companyName", "department", "displayName",
    "employeeId", "facsimileTelephoneNumber", "givenName", "jobTitle",
    "mail", "mailNickName", "mobile", "objectId",
    "onPremisesDistinguishedName", "onPremisesSecurityIdentifier",
    "passwordPolicies", "physicalDeliveryOfficeName", "postalCode",
    "preferredLanguage", "sipProxyAddress", "state", "streetAddress",
    "surname", "telephoneNumber", "usageLocation", "userPrincipalName",
    "userType",
})

# Okta base-profile attribute -> Entra user property. Each target is in the
# list above *and* is written by import_users.py when it creates a user,
# so a translated rule has data to match on. countryCode is ISO 3166
# alpha-2, which is what Entra's usageLocation holds (Entra's `country`
# is free text, so it is not a safe target).
ATTR_MAP = {
    "login": "userPrincipalName",
    "email": "mail",
    "firstName": "givenName",
    "lastName": "surname",
    "title": "jobTitle",
    "department": "department",
    "city": "city",
    "state": "state",
    "streetAddress": "streetAddress",
    "zipCode": "postalCode",
    "countryCode": "usageLocation",
    "organization": "companyName",
    "employeeNumber": "employeeId",
    "mobilePhone": "mobile",
}

# Attributes people commonly use in Okta rules that have no documented
# Entra dynamic-rule property. Named so the problem message can say so.
NO_ENTRA_EQUIVALENT = {
    "costCenter", "division", "employeeType", "manager", "managerId",
    "userType", "nickName", "displayName", "secondEmail", "timezone",
    "locale", "honorificPrefix", "honorificSuffix", "middleName",
}

MAX_ENTRA_RULE_LENGTH = 3072

_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<op>==|!=|&&|\|\||>=|<=|[!(),.<>?:{}])
  | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<num>\d+(?:\.\d+)?)
""", re.VERBOSE)


class Unsupported(ValueError):
    """The expression uses something this translator won't translate."""


def _unquote(tok: str) -> str:
    body = tok[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


def tokenize(expr: str) -> list[tuple[str, str]]:
    toks, pos = [], 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise Unsupported(f"can't parse near {expr[pos:pos + 20]!r}")
        pos = m.end()
        if m.lastgroup != "ws":
            toks.append((m.lastgroup, m.group(0)))
    return toks


# AST nodes are tuples:
#   ("and", a, b) ("or", a, b) ("not", a)
#   ("cmp", okta_attr, op, value)   op in eq/ne/contains/startsWith,
#                                   value is a str or None (null)

class _Parser:
    def __init__(self, toks):
        self.toks, self.pos = toks, 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def next(self):
        t = self.peek()
        self.pos += 1
        return t

    def expect(self, val):
        kind, tok = self.next()
        if tok != val:
            raise Unsupported(f"expected {val!r}, got {tok!r}")

    def is_or(self):
        k, t = self.peek()
        return t == "||" or (k == "word" and t.upper() == "OR")

    def is_and(self):
        k, t = self.peek()
        return t == "&&" or (k == "word" and t.upper() == "AND")

    def parse(self):
        node = self.or_()
        if self.pos != len(self.toks):
            raise Unsupported(f"unexpected {self.peek()[1]!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.is_or():
            self.next()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.unary()
        while self.is_and():
            self.next()
            node = ("and", node, self.unary())
        return node

    def unary(self):
        if self.peek()[1] == "!":
            self.next()
            return ("not", self.unary())
        if self.peek()[1] == "(":
            self.next()
            node = self.or_()
            self.expect(")")
            return node
        return self.comparison()

    def attr(self) -> str:
        kind, tok = self.next()
        if tok != "user":
            raise Unsupported(f"only user.<attribute> is supported, got {tok!r}")
        self.expect(".")
        kind, name = self.next()
        if kind != "word":
            raise Unsupported(f"expected an attribute name, got {name!r}")
        if self.peek()[1] == "(":
            raise Unsupported(f"user.{name}(...) has no Entra equivalent")
        return name

    def value(self):
        kind, tok = self.next()
        if kind == "str":
            return _unquote(tok)
        if kind == "word" and tok == "null":
            return None
        raise Unsupported(f"expected a string literal or null, got {tok!r}")

    def comparison(self):
        kind, tok = self.peek()
        if tok == "String":
            self.next()
            self.expect(".")
            _, fn = self.next()
            ops = {"stringContains": "contains", "startsWith": "startsWith"}
            if fn not in ops:
                raise Unsupported(f"String.{fn} isn't translated")
            self.expect("(")
            name = self.attr()
            self.expect(",")
            val = self.value()
            self.expect(")")
            if val is None:
                raise Unsupported(f"String.{fn} with null")
            return ("cmp", name, ops[fn], val)
        if tok in ("Arrays", "Groups", "Convert", "Iso3166Convert", "Time"):
            raise Unsupported(f"{tok}.* functions aren't translated")
        if kind == "word" and tok.startswith("isMemberOf"):
            raise Unsupported(f"{tok} (group-membership rules) needs a "
                              f"manual rewrite, e.g. Entra memberOf (preview)")
        if tok != "user":
            raise Unsupported(f"unsupported term {tok!r}")
        name = self.attr()
        kind, op = self.peek()
        if op in ("==", "!="):
            self.next()
            return ("cmp", name, "eq" if op == "==" else "ne", self.value())
        if kind == "word" and op == "matches":
            raise Unsupported("'matches' (regex) isn't translated: Okta and "
                              "Entra regex dialects differ")
        if op in ("<", ">", "<=", ">="):
            raise Unsupported(f"numeric comparison {op!r} isn't translated")
        raise Unsupported(f"user.{name} used without a comparison "
                          f"(boolean attribute?)")


def parse(expr: str):
    if not expr or not expr.strip():
        raise Unsupported("empty rule expression")
    return _Parser(tokenize(expr)).parse()


def _attrs(node, out):
    if node[0] == "cmp":
        out.append(node[1])
    else:
        for child in node[1:]:
            _attrs(child, out)
    return out


def _entra_string(val):
    if val is None:
        return "null"
    if "`" in val:
        raise Unsupported("value contains a backtick, which Entra uses as "
                          "its escape character")
    return '"' + val.replace('"', '`"') + '"'


def emit(node) -> str:
    kind = node[0]
    if kind == "cmp":
        _, name, op, val = node
        prop = ATTR_MAP[name]
        if val is None and op not in ("eq", "ne"):
            raise Unsupported("null only works with -eq / -ne")
        entra_op = {"eq": "-eq", "ne": "-ne", "contains": "-contains",
                    "startsWith": "-startsWith"}[op]
        return f"(user.{prop} {entra_op} {_entra_string(val)})"
    if kind == "not":
        return f"-not {emit(node[1])}"
    left, right = emit(node[1]), emit(node[2])
    return f"({left} -{kind} {right})"


def evaluate(node, profile: dict) -> bool:
    """Evaluate a parsed rule against an Okta profile (Okta semantics:
    case-sensitive string comparison; a missing attribute is null)."""
    kind = node[0]
    if kind == "and":
        return evaluate(node[1], profile) and evaluate(node[2], profile)
    if kind == "or":
        return evaluate(node[1], profile) or evaluate(node[2], profile)
    if kind == "not":
        return not evaluate(node[1], profile)
    _, name, op, val = node
    actual = profile.get(name)
    if op == "eq":
        return actual == val
    if op == "ne":
        return actual != val
    if actual is None:
        return False
    actual = str(actual)
    if op == "contains":
        return val in actual
    return actual.startswith(val)


class Translation:
    """Result of translating one Okta expression."""

    def __init__(self, okta: str):
        self.okta = okta
        self.ast = None
        self.entra: str | None = None
        self.problems: list[str] = []
        self.notes: list[str] = []

    @property
    def ok(self) -> bool:
        return self.entra is not None


def translate(expr: str) -> Translation:
    t = Translation(expr)
    try:
        t.ast = parse(expr)
        unmapped = []
        for name in _attrs(t.ast, []):
            if name in ATTR_MAP:
                if ATTR_MAP[name] not in ENTRA_DYNAMIC_USER_STRING_PROPS:
                    unmapped.append(f"{name} (maps to {ATTR_MAP[name]}, "
                                    f"which Entra rules don't support)")
            elif name in NO_ENTRA_EQUIVALENT:
                unmapped.append(f"{name} (no Entra dynamic-rule property; "
                                f"consider an extensionAttribute)")
            else:
                unmapped.append(f"{name} (not mapped; custom attribute?)")
        if unmapped:
            raise Unsupported("attribute(s) without a supported Entra "
                              "property: " + ", ".join(sorted(set(unmapped))))
        entra = emit(t.ast)
    except Unsupported as e:
        t.problems.append(str(e))
        return t
    if len(entra) > MAX_ENTRA_RULE_LENGTH:
        t.problems.append(f"translated rule is {len(entra)} characters; "
                          f"Entra allows {MAX_ENTRA_RULE_LENGTH}")
        return t
    t.entra = entra
    if any(n[0] == "cmp" and n[2] in ("eq", "ne", "contains", "startsWith")
           for n in _walk(t.ast)):
        t.notes.append("Entra compares strings case-insensitively; check the "
                       "Okta rule didn't depend on letter case")
    return t


def _walk(node):
    yield node
    if node[0] != "cmp":
        for child in node[1:]:
            yield from _walk(child)


def combine_or(translations: list[Translation]) -> str:
    """OR several translated rules into one Entra rule body."""
    parts = [t.entra for t in translations]
    if len(parts) == 1:
        return parts[0]
    return "(" + " -or ".join(parts) + ")"
