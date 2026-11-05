"""Presentation checks for the original-layout login variant."""
from pathlib import Path
import unittest


class LoginLayoutTest(unittest.TestCase):
    def test_original_shell_and_secondary_buttons(self):
        root = Path(__file__).resolve().parents[1] / 'nipap-www/nipapwww'
        template = (root / 'templates/login.html').read_text()
        self.assertIn('{% extends "base.html" %}', template)
        self.assertIn('css/login.css', template)
        self.assertIn('<dt>Or log in with</dt>', template)
        self.assertLess(template.index('value="Log in"'),
                        template.index('class="login-auth-methods"'))
        self.assertNotIn('<details', template)


if __name__ == '__main__':
    unittest.main()
