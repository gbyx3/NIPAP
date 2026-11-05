"""Presentation checks for the provider dropdown variant."""
from pathlib import Path
import unittest


class LoginLayoutTest(unittest.TestCase):
    def test_only_alternative_methods_are_collapsed(self):
        root = Path(__file__).resolve().parents[1] / 'nipap-www/nipapwww'
        template = (root / 'templates/login.html').read_text()
        self.assertIn('{% extends "base.html" %}', template)
        self.assertIn('<details class="login-method-picker">', template)
        self.assertLess(template.index('value="Log in"'), template.index('<details'))
        self.assertIn("url_for('oidc.begin', provider_name=provider)", template)
        self.assertIn('name="_csrf"', template)


if __name__ == '__main__':
    unittest.main()
