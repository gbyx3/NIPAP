"""Browser-hardening regressions using local authentication only."""
from pathlib import Path
import configparser
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from flask import Flask
from nipapwww import auth, create_app
from nipapwww.web_security import init_app, local_return_path


class BrowserSecurityTest(unittest.TestCase):
    def make_app(self, enabled=True):
        app = Flask('security-test', template_folder=str(Path(auth.__file__).parent / 'templates'))
        app.config.update(SECRET_KEY='test-only', TESTING=True)
        if enabled:
            init_app(app)
        app.register_blueprint(auth.bp)
        app.add_url_rule('/prefix', endpoint='prefix.list', view_func=lambda: '')
        app.add_url_rule('/version', endpoint='version.show_version', view_func=lambda: '')
        app.add_url_rule('/write', endpoint='xhr.remove_prefix', view_func=lambda: 'written', methods=['GET', 'POST'])
        app.add_url_rule('/filter', endpoint='xhr.add_current_vrf', view_func=lambda: 'filtered', methods=['GET', 'POST'])
        return app

    def setUp(self):
        self.app = self.make_app()
        self.client = self.app.test_client()
        self.base = 'https://ipam.example.test'
        self.client.get('/auth/login', base_url=self.base)

    def token(self):
        with self.client.session_transaction(base_url=self.base) as current:
            return current['_csrf']

    def test_mutations_require_post_and_csrf(self):
        self.assertEqual(self.client.get('/write', base_url=self.base).status_code, 405)
        self.assertEqual(self.client.post('/write', base_url=self.base).status_code, 403)
        self.assertEqual(self.client.post('/write', base_url=self.base, headers={
            'X-XSRF-TOKEN': self.token()}).status_code, 200)

    def test_readonly_rejects_writes_but_allows_session_filter(self):
        with self.client.session_transaction(base_url=self.base) as current:
            current.update(user='reader', readonly=True)
        headers = {'X-XSRF-TOKEN': self.token()}
        self.assertEqual(self.client.post('/write', base_url=self.base, headers=headers).status_code, 403)
        self.assertEqual(self.client.post('/filter', base_url=self.base, headers=headers).status_code, 200)

    def test_local_login_and_logout_with_csrf(self):
        account = SimpleNamespace(authenticate=lambda: True, username='reader',
                                  authenticated_as='reader', auth_backend='local',
                                  full_name='Example Reader', readonly=True)
        with patch.object(auth, 'AuthFactory') as factory:
            factory.return_value.get_auth.return_value = account
            response = self.client.post('/auth/login', base_url=self.base, data={
                'username': 'reader', 'password': 'test-only', '_csrf': self.token()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/auth/logout', base_url=self.base).status_code, 405)
        self.assertEqual(self.client.post('/auth/logout', base_url=self.base).status_code, 403)
        self.assertEqual(self.client.post('/auth/logout', base_url=self.base, data={
            '_csrf': self.token()}).status_code, 200)
        with self.client.session_transaction(base_url=self.base) as current:
            self.assertNotIn('user', current)

    def test_legacy_mode_retains_get_logout_and_does_not_set_csrf(self):
        client = self.make_app(enabled=False).test_client()
        response = client.get('/auth/logout')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('XSRF-TOKEN=', '\n'.join(response.headers.getlist('Set-Cookie')))
        self.assertEqual(client.get('/write').status_code, 200)

    def test_unsafe_return_paths_rejected(self):
        for value in ['https://evil.test', '//evil.test', '/\\evil', '/\nevil',
                      ' /evil', None, 123]:
            self.assertEqual(local_return_path(value, '/prefix'), '/prefix')
        self.assertEqual(local_return_path('/prefix?q=test'), '/prefix?q=test')

    def test_native_login_cannot_redirect_off_site(self):
        account = SimpleNamespace(authenticate=lambda: True, username='reader',
                                  authenticated_as='reader', auth_backend='local',
                                  full_name='Example Reader', readonly=True)
        for destination in ['https://evil.test', '//evil.test', '/\\evil', 123]:
            with self.client.session_transaction(base_url=self.base) as current:
                current['path_before_login'] = destination
            with patch.object(auth, 'AuthFactory') as factory:
                factory.return_value.get_auth.return_value = account
                response = self.client.post('/auth/login', base_url=self.base, data={
                    'username': 'reader', 'password': 'test-only', '_csrf': self.token()})
            self.assertEqual(response.location, '/prefix')

    def test_secure_cookie_and_auth_headers(self):
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        cookies = '\n'.join(response.headers.getlist('Set-Cookie'))
        self.assertIn('Secure', cookies)
        self.assertIn('SameSite=Strict', cookies)
        self.assertIn(b'name="_csrf"', response.data)

    def test_legacy_jquery_add_prefix_uses_json_post(self):
        script = (Path(auth.__file__).parent / 'static/nipap.js').read_text()
        self.assertNotIn("$.getJSON('/xhr/add_prefix'", script)
        self.assertIn("url: '/xhr/add_prefix', type: 'POST', contentType: 'application/json'", script)
        self.assertIn("xhr.setRequestHeader('X-XSRF-TOKEN'", script)


class SecurityFactoryTest(unittest.TestCase):
    def test_explicit_opt_in_without_oidc(self):
        config = configparser.ConfigParser()
        config.read_dict({'www': {'xmlrpc_uri': 'http://backend.example.test/',
                                  'secret_key': 'test-only'}})
        for enabled in (False, 'false', 'no', True, 'true', 'yes'):
            with patch('nipap.nipapconfig.NipapConfig', return_value=config):
                app = create_app({'TESTING': True, 'WEB_SECURITY_ENABLED': enabled})
            self.assertEqual(bool(app.extensions.get('nipap_web_security')),
                             enabled in (True, 'true', 'yes'))
            self.assertNotIn('nipap_oidc', app.extensions)
