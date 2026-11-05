"""Presentation checks for the inline login-method variant."""
from pathlib import Path
import unittest


class LoginLayoutTest(unittest.TestCase):
    def test_provider_buttons_use_separate_forms(self):
        root = Path(__file__).resolve().parents[1] / 'nipap-www/nipapwww'
        template = (root / 'templates/login.html').read_text()
        self.assertIn('{% extends "base.html" %}', template)
        self.assertIn('form="login-provider-{{ provider }}"', template)
        self.assertIn('<form id="login-provider-{{ provider }}"', template)
        self.assertIn('name="_csrf"', template)
        self.assertNotIn('<dt>Or log in with</dt>', template)


if __name__ == '__main__':
    unittest.main()
