"""Request-boundary tests without an identity provider or backend service."""
import unittest

from flask import Flask
from nipapwww import auth
from pynipap import AuthOptions, NipapMissingInputError


class AuthLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(SECRET_KEY='test-only', TESTING=True)
        self.app.register_blueprint(auth.bp)
        self.app.add_url_rule('/identity', view_func=lambda: dict(AuthOptions().options))
        self.client = self.app.test_client()
        AuthOptions.clear()
        self.addCleanup(AuthOptions.clear)

    def test_request_identity_is_cleared_after_response(self):
        with self.client.session_transaction() as session:
            session.update(user='reader', readonly=True)
        response = self.client.get('/identity')
        self.assertEqual(response.json['username'], 'reader')
        self.assertTrue(response.json['readonly'])
        with self.assertRaises(NipapMissingInputError):
            AuthOptions()

    def test_anonymous_request_does_not_reuse_previous_identity(self):
        with self.client.session_transaction() as session:
            session.update(user='administrator', readonly=False)
        self.client.get('/identity')
        with self.client.session_transaction() as session:
            session.clear()
        self.assertIsNone(self.client.get('/identity').json['username'])

    def test_exception_also_clears_identity(self):
        def fail():
            raise RuntimeError('synthetic request failure')
        self.app.add_url_rule('/fail', view_func=fail)
        with self.assertRaises(RuntimeError):
            self.client.get('/fail')
        with self.assertRaises(NipapMissingInputError):
            AuthOptions()
