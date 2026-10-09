"""Okta group-rule expression -> Entra dynamic membership rule."""

import unittest

import _paths  # noqa: F401
import rule_translator as rt

# (Okta expression, expected Entra rule)
GOLDEN = [
    ('user.department == "Engineering"',
     '(user.department -eq "Engineering")'),
    ('user.department != "Sales"',
     '(user.department -ne "Sales")'),
    ("user.title == 'Engineer'",
     '(user.jobTitle -eq "Engineer")'),
    ('String.stringContains(user.email, "@example.com")',
     '(user.mail -contains "@example.com")'),
    ('String.startsWith(user.login, "svc")',
     '(user.userPrincipalName -startsWith "svc")'),
    ('user.department == "Eng" AND user.city == "Austin"',
     '((user.department -eq "Eng") -and (user.city -eq "Austin"))'),
    ('user.department == "Eng" && user.city == "Austin"',
     '((user.department -eq "Eng") -and (user.city -eq "Austin"))'),
    ('user.city == "Austin" OR user.city == "Dallas"',
     '((user.city -eq "Austin") -or (user.city -eq "Dallas"))'),
    ('user.department == "Sales" AND !(user.title == "SDE")',
     '((user.department -eq "Sales") -and -not (user.jobTitle -eq "SDE"))'),
    ('user.a == "1" OR user.department == "x"', None),   # unmapped attr
    ('user.countryCode == "GB"',
     '(user.usageLocation -eq "GB")'),
    ('user.employeeNumber == null',
     '(user.employeeId -eq null)'),
    ('user.department == "R\\"D"',
     '(user.department -eq "R`"D")'),
    # precedence: AND binds tighter than OR
    ('user.city == "A" OR user.city == "B" AND user.state == "TX"',
     '((user.city -eq "A") -or ((user.city -eq "B") -and (user.state -eq "TX")))'),
]

MANUAL = [
    'user.costCenter == "FIN"',
    'user.division == "EMEA"',
    'user.employeeType == "Contractor"',
    'isMemberOfAnyGroup("00g1", "00g2")',
    "user.title matches '(?i)engineer'",
    'Arrays.contains(user.favoriteColors, "blue")',
    'user.getInternalProperty("status") == "ACTIVE"',
    "user.isContractor",
    "user.salary > 100",
    'user.department == "a`b"',
    "",
    'user.department == ',
]


class TranslateTest(unittest.TestCase):
    def test_golden(self):
        for okta, expected in GOLDEN:
            with self.subTest(okta=okta):
                t = rt.translate(okta)
                self.assertEqual(t.entra, expected, t.problems)
                if expected is None:
                    self.assertTrue(t.problems)

    def test_manual_items_are_flagged_with_a_reason(self):
        for okta in MANUAL:
            with self.subTest(okta=okta):
                t = rt.translate(okta)
                self.assertIsNone(t.entra)
                self.assertTrue(t.problems and all(t.problems))

    def test_never_emits_bare_logical_operators(self):
        for _okta, expected in GOLDEN:
            if expected:
                padded = f" {expected} "
                for bare in (" and ", " or ", "(not "):
                    self.assertNotIn(bare, padded)

    def test_every_mapped_property_is_documented_for_dynamic_rules(self):
        self.assertTrue(set(rt.ATTR_MAP.values())
                        <= rt.ENTRA_DYNAMIC_USER_STRING_PROPS)
        for gone in ("employeeType", "division", "costCenter", "country"):
            self.assertNotIn(gone, rt.ATTR_MAP.values())

    def test_too_long_rule_is_flagged(self):
        expr = " OR ".join(f'user.city == "{"x" * 40}{i}"' for i in range(80))
        t = rt.translate(expr)
        self.assertIsNone(t.entra)
        self.assertIn("3072", " ".join(t.problems))

    def test_combine_or(self):
        a = rt.translate('user.city == "A"')
        b = rt.translate('user.city == "B"')
        self.assertEqual(rt.combine_or([a, b]),
                         '((user.city -eq "A") -or (user.city -eq "B"))')
        self.assertEqual(rt.combine_or([a]), '(user.city -eq "A")')


class EvaluateTest(unittest.TestCase):
    def test_okta_semantics(self):
        ast = rt.parse('user.department == "Eng" AND !(user.title == "Intern")')
        self.assertTrue(rt.evaluate(ast, {"department": "Eng", "title": "SWE"}))
        self.assertFalse(rt.evaluate(ast, {"department": "Eng", "title": "Intern"}))
        self.assertFalse(rt.evaluate(ast, {"department": "eng"}))  # case matters
        contains = rt.parse('String.stringContains(user.email, "@x.com")')
        self.assertTrue(rt.evaluate(contains, {"email": "a@x.com"}))
        self.assertFalse(rt.evaluate(contains, {}))
        null = rt.parse("user.city == null")
        self.assertTrue(rt.evaluate(null, {}))


if __name__ == "__main__":
    unittest.main()
