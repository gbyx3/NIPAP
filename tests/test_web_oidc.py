"""Offline OIDC boundary tests using real signatures and one-use state."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import configparser
import os
from html.parser import HTMLParser
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

try:
    from joserfc import jwt
    from joserfc.jwk import RSAKey, OctKey
    from nipapwww.oidc import LoginRejected, Provider, Transactions, local_return_path
    from nipapwww.oidc import init_app
except ModuleNotFoundError as error:
    if error.name not in ('authlib', 'joserfc', 'requests'):
        raise
    raise unittest.SkipTest('Install the nipap-www oidc extra to run OIDC tests')
from flask import Flask, session
import requests
from types import SimpleNamespace
from nipapwww import auth
from nipapwww import create_app


class TransactionsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Transactions(Path(self.directory.name) / 'state.db')

    def test_one_use_and_browser_provider_binding(self):
        state, expected = self.store.create('piv', 'browser')
        for provider, binding in [('bio', 'browser'), ('piv', 'other')]:
            with self.assertRaises(LoginRejected):
                self.store.consume(state, provider, binding)
        self.assertEqual(self.store.consume(state, 'piv', 'browser'), expected)
        with self.assertRaises(LoginRejected):
            self.store.consume(state, 'piv', 'browser')

    def test_concurrent_consumption_has_exactly_one_winner(self):
        state, _ = self.store.create('bio', 'browser')

        def consume():
            try:
                self.store.consume(state, 'bio', 'browser')
                return True
            except LoginRejected:
                return False

        with ThreadPoolExecutor(max_workers=4) as executor:
            self.assertEqual(sum(executor.map(lambda _: consume(), range(4))), 1)

    def test_expired_and_capacity(self):
        self.store.capacity = 1
        state, _ = self.store.create('bio', 'browser')
        with self.assertRaises(LoginRejected):
            self.store.create('bio', 'browser')
        with self.store.connect() as db:
            db.execute('UPDATE transactions SET expires = 0')
        with self.assertRaises(LoginRejected):
            self.store.consume(state, 'bio', 'browser')
        self.store.create('bio', 'browser')

    def test_unsafe_redirects(self):
        for value in ['https://evil.test', '//evil.test', '/\\evil', '/\nevil',
                      ' /evil', None]:
            self.assertEqual(local_return_path(value), '/')
        self.assertEqual(local_return_path('/ng/prefix?q=x'), '/ng/prefix?q=x')


class ProviderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey.generate_key(2048)
        cls.other = RSAKey.generate_key(2048)

    def setUp(self):
        self.config = dict(issuer='https://idp.test/issuer',
                           authorization_endpoint='https://idp.test/authorize',
                           token_endpoint='https://idp.test/token',
                           jwks_uri='https://idp.test/jwks',
                           redirect_uri='https://nipap.test/auth/oidc/bio/callback',
                           client_id='nipap', client_secret='test-only',
                           identities={'immutable-subject': dict(
                               username='reader', readonly=True,
                               required_claims={'sid': 'exact-sid', 'acr': 'bio-uv'})})
        self.provider = Provider(self.config)
        now = int(time.time())
        self.claims = dict(iss=self.config['issuer'], aud='nipap',
                           sub='immutable-subject', nonce='test-nonce',
                           iat=now, auth_time=now, exp=now + 600,
                           sid='exact-sid', acr='bio-uv')

    def validate(self, claims=None, key=None, algorithm='RS256'):
        encoded = jwt.encode({'alg': algorithm}, self.claims if claims is None else claims,
                             key or self.key)
        return self.provider.validate(encoded, 'test-nonce', self.key)

    def test_valid_identity_is_server_mapped_readonly(self):
        self.claims.update(readonly=False, username='admin')
        identity = self.validate()
        self.assertTrue(identity['readonly'])
        self.assertEqual(identity['username'], 'reader')

    def test_explicit_immutable_directory_claim_and_resource_scopes(self):
        self.provider = Provider(dict(self.config, identity_claim='directory_id',
            identities={'directory-object': dict(username='reader', readonly=True)},
            scopes=['openid', 'https://resource.example.test/allatclaims']))
        with self.assertRaises(LoginRejected):
            self.validate()
        result = self.validate(dict(self.claims, directory_id='directory-object'))
        self.assertEqual(result['identity_key'], 'directory-object')
        self.assertEqual(result['subject'], self.claims['sub'])
        url = self.provider.authorization_url('state', dict(nonce='nonce', verifier='v' * 64))
        self.assertIn('https://resource.example.test/allatclaims',
                      parse_qs(urlsplit(url).query)['scope'][0].split())

    def test_wrong_issuer_audience_subject_nonce_assurance(self):
        for key, value in [('iss', 'https://other.test'), ('aud', 'other-client'),
                           ('sub', 'other-user'), ('nonce', 'other-nonce'),
                           ('sid', 'other-sid'), ('acr', 'password'),
                           ('azp', 'other-client')]:
            with self.subTest(claim=key), self.assertRaises(LoginRejected):
                self.validate(dict(self.claims, **{key: value}))

    def test_required_claims_and_times(self):
        for key in ['iss', 'aud', 'sub', 'nonce', 'exp', 'iat', 'auth_time', 'acr']:
            claims = dict(self.claims)
            del claims[key]
            with self.subTest(missing=key), self.assertRaises(LoginRejected):
                self.validate(claims)
        for key, value in [('exp', 1), ('iat', time.time() + 500),
                           ('auth_time', 1), ('auth_time', 'now'),
                           ('exp', float('inf')), ('auth_time', float('nan'))]:
            with self.subTest(invalid=key), self.assertRaises(LoginRejected):
                self.validate(dict(self.claims, **{key: value}))

    def test_multiple_audiences_require_matching_azp(self):
        claims = dict(self.claims, aud=['nipap', 'other'])
        with self.assertRaises(LoginRejected):
            self.validate(claims)
        self.validate(dict(claims, azp='nipap'))

    def test_bad_signature_and_algorithm(self):
        with self.assertRaises(LoginRejected):
            self.validate(key=self.other)
        with self.assertRaises(LoginRejected):
            self.validate(key=OctKey.generate_key(256), algorithm='HS256')
        with self.assertRaises(LoginRejected):
            self.provider.validate('not.a.token', 'test-nonce', self.key)

    def test_authorization_url_has_pkce_nonce_and_state(self):
        transaction = dict(verifier='a' * 64, nonce='test-nonce')
        url = self.provider.authorization_url('test-state', transaction)
        query = parse_qs(urlsplit(url).query)
        for key, value in [('state', 'test-state'), ('nonce', 'test-nonce'),
                           ('code_challenge_method', 'S256'), ('response_type', 'code')]:
            self.assertEqual(query[key], [value])
        self.assertNotIn(transaction['verifier'], url)
        self.assertIn('code_challenge', query)

    def test_insecure_configuration_rejected(self):
        for key in ['issuer', 'token_endpoint', 'authorization_endpoint',
                    'jwks_uri', 'redirect_uri']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                Provider(dict(self.config, **{key: 'http://insecure.test'}))
        with self.assertRaises(ValueError):
            Provider(dict(self.config, algorithms=['HS256']))
        with self.assertRaises(ValueError):
            Provider(dict(self.config, ca_bundle=False)).client()

    def test_code_exchange_uses_pkce_fixed_endpoints_and_real_signature(self):
        transaction = dict(nonce='test-nonce', verifier='v' * 64)
        calls = []
        encoded = jwt.encode({'alg': 'RS256'}, self.claims, self.key)

        def send(client, prepared, **kwargs):
            calls.append(prepared.url)
            self.assertFalse(kwargs['allow_redirects'])
            self.assertTrue(kwargs['verify'])
            self.assertEqual(kwargs['timeout'], (5, 15))
            response = requests.Response()
            response.status_code = 200
            response._content_consumed = True
            if prepared.url == self.config['token_endpoint']:
                self.assertEqual(prepared.method, 'POST')
                form = parse_qs(prepared.body)
                self.assertEqual(form['code_verifier'], [transaction['verifier']])
                self.assertEqual(form['redirect_uri'], [self.config['redirect_uri']])
                self.assertEqual(form['code'], ['test-code'])
                self.assertTrue(prepared.headers['Authorization'].startswith('Basic '))
                data = dict(access_token='test-only-access', token_type='Bearer', id_token=encoded)
            elif prepared.url == self.config['jwks_uri']:
                data = dict(keys=[self.key.as_dict(private=False)])
            else:
                self.fail('Unexpected outbound request')
            response._content = json.dumps(data).encode()
            return response

        with patch.object(requests.Session, 'send', autospec=True, side_effect=send):
            identity = self.provider.exchange('test-code', transaction)
        self.assertEqual(identity['username'], 'reader')
        self.assertEqual(calls, [self.config['token_endpoint'], self.config['jwks_uri']])

    def test_exchange_errors_do_not_expose_token_or_provider_response(self):
        with patch.object(requests.Session, 'send', side_effect=ValueError('sensitive-value')):
            with self.assertRaises(LoginRejected) as result:
                self.provider.exchange('test-code', dict(nonce='n', verifier='v' * 64))
        self.assertNotIn('sensitive-value', str(result.exception))


class BrowserTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = Flask('oidc-test', template_folder=str(
            Path(auth.__file__).parent / 'templates'))
        self.app.config.update(SECRET_KEY='test-only', TESTING=True)
        self.config = dict(issuer='https://idp.test/',
                           authorization_endpoint='https://idp.test/authorize',
                           token_endpoint='https://idp.test/token',
                           jwks_uri='https://idp.test/jwks',
                           redirect_uri='https://nipap.test/auth/oidc/bio/callback',
                           client_id='test-client', client_secret='test-only',
                           identities={'subject': dict(username='reader', readonly=True)})
        init_app(self.app, dict(transaction_db=str(Path(self.directory.name) / 'state.db'),
                                 providers={'bio': self.config}))
        self.app.register_blueprint(auth.bp)
        self.app.add_url_rule('/prefix', endpoint='prefix.list', view_func=lambda: '')
        self.app.add_url_rule('/version', endpoint='version.show_version', view_func=lambda: '')
        self.app.add_url_rule('/', view_func=lambda: 'test')
        self.app.add_url_rule('/write', endpoint='xhr.remove_prefix',
                              view_func=lambda: 'written', methods=['GET', 'POST'])
        self.app.add_url_rule('/identity', endpoint='identity', view_func=lambda: dict(session))
        self.client = self.app.test_client()
        self.base = 'https://nipap.test'
        self.client.get('/', base_url=self.base)

    def test_local_fallback_and_login_buttons(self):
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'/auth/oidc/bio/login', response.data)
        self.assertIn(b'name="password"', response.data)
        account = SimpleNamespace(authenticate=lambda: True, username='local-admin',
                                  authenticated_as='local-admin', auth_backend='local',
                                  full_name='Local Admin', readonly=False)
        with patch.object(auth, 'AuthFactory') as factory:
            factory.return_value.get_auth.return_value = account
            response = self.client.post('/auth/login', base_url=self.base, data={
                'username': 'local-admin', 'password': 'test-only', '_csrf': self.csrf()})
        self.assertEqual(response.status_code, 302)
        current = self.client.get('/identity', base_url=self.base).get_json()
        self.assertEqual(current['authenticated_identity'], 'local-admin@local')
        self.assertNotIn('_oidc_provider', current)
        self.assertEqual(self.client.get('/auth/logout', base_url=self.base).status_code, 405)
        self.assertEqual(self.client.post('/auth/logout', base_url=self.base,
            data={'_csrf': self.csrf()}).status_code, 200)
        self.assertNotIn('user', self.client.get('/identity', base_url=self.base).get_json())

    def test_auth_choices_are_inside_panel_without_nested_forms(self):
        provider = self.app.extensions['nipap_oidc']['providers']['bio']
        provider.config['label'] = '<script>untrusted label</script>'

        class LoginParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.stack, self.forms = [], []
                self.form_depth = 0
                self.nested = False

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form':
                    self.nested = self.nested or self.form_depth > 0
                    self.form_depth += 1
                    inside = any('options-group' in a.get('class', '').split()
                                 for _, a in self.stack)
                    self.forms.append((attrs.get('action'), inside))
                if tag not in ('input', 'link', 'meta', 'img', 'br', 'hr'):
                    self.stack.append((tag, attrs))

            def handle_endtag(self, tag):
                if tag == 'form':
                    self.form_depth -= 1
                for index in range(len(self.stack) - 1, -1, -1):
                    if self.stack[index][0] == tag:
                        del self.stack[index:]
                        break

        response = self.client.get('/auth/login', base_url=self.base)
        parser = LoginParser()
        parser.feed(response.get_data(as_text=True))
        login_forms = [(action, inside) for action, inside in parser.forms
                       if action in ('/auth/login', '/auth/oidc/bio/login')]
        self.assertEqual(len(login_forms), 2)
        self.assertTrue(all(inside for _, inside in login_forms))
        self.assertFalse(parser.nested)
        self.assertIn(b'&lt;script&gt;untrusted label&lt;/script&gt;', response.data)
        self.assertNotIn(b'<script>untrusted label</script>', response.data)

    def test_local_login_is_always_visible_and_precedes_alternatives(self):
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertNotIn(b'<details', response.data)
        self.assertLess(response.data.index(b'class="auth-local-form"'),
                        response.data.index(b'class="login-auth-methods"'))
        self.assertIn(b'name="username"', response.data)
        self.assertIn(b'name="password"', response.data)

    def test_failed_local_login_keeps_visible_form(self):
        account = SimpleNamespace(authenticate=lambda: False)
        with patch.object(auth, 'AuthFactory') as factory:
            factory.return_value.get_auth.return_value = account
            response = self.client.post('/auth/login', base_url=self.base, data={
                'username': 'invalid', 'password': 'test-only', '_csrf': self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'<details', response.data)
        self.assertIn(b'class="auth-local-form"', response.data)
        self.assertIn(b'Invalid username or password', response.data)

    def test_login_preserves_application_shell_and_uses_local_assets(self):
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="viewport"', response.data)
        self.assertIn(b'css/nipap.css', response.data)
        self.assertIn(b'id="login-heading"', response.data)
        self.assertIn(b'role="switch"', response.data)
        self.assertIn(b'class="top_menu"', response.data)
        self.assertNotIn(b'>Log out<', response.data)

    def test_dedicated_login_notice_is_escaped(self):
        self.app.config.update(WELCOME_MESSAGE='outdated application message',
                               LOGIN_NOTICE='<script>access notice</script>')
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertIn(b'&lt;script&gt;access notice&lt;/script&gt;', response.data)
        self.assertNotIn(b'<script>access notice</script>', response.data)
        self.assertNotIn(b'outdated application message', response.data)

    def csrf(self):
        with self.client.session_transaction(base_url=self.base) as current:
            return current['_csrf']

    def start(self):
        response = self.client.post('/auth/oidc/bio/login', base_url=self.base,
                                    data={'_csrf': self.csrf()})
        self.assertEqual(response.status_code, 302)
        return parse_qs(urlsplit(response.location).query)['state'][0]

    def test_csrf_and_mutating_get_rejected(self):
        self.assertEqual(self.client.post('/auth/oidc/bio/login',
                                         base_url=self.base).status_code, 403)
        self.assertEqual(self.client.get('/write', base_url=self.base).status_code, 405)
        self.assertEqual(self.client.post('/write', base_url=self.base).status_code, 403)

    def test_callback_identity_replay_and_no_tokens_in_session(self):
        state = self.start()
        identity = dict(username='reader', full_name='Reader', readonly=True,
                        subject='subject', identity_key='subject', expires=time.time() + 300)
        provider = self.app.extensions['nipap_oidc']['providers']['bio']
        with patch.object(provider, 'exchange', return_value=identity) as exchange:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                                       query_string={'state': state, 'code': 'one-use-code'})
            self.assertEqual(response.status_code, 302)
            exchange.assert_called_once()
            self.assertEqual(self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'one-use-code'}).status_code, 400)
            exchange.assert_called_once()
        current = self.client.get('/identity', base_url=self.base).get_json()
        self.assertTrue(current['readonly'])
        self.assertEqual(current['authenticated_identity'], 'subject@oidc:bio')
        for forbidden in ['id_token', 'access_token', 'refresh_token', 'verifier', '_oidc_binding']:
            self.assertNotIn(forbidden, current)
        self.assertEqual(self.client.post('/write', base_url=self.base,
            headers={'X-XSRF-TOKEN': self.csrf()}).status_code, 403)

    def test_unknown_provider_and_duplicate_parameters(self):
        self.assertEqual(self.client.get('/auth/oidc/unknown/callback',
                                         base_url=self.base).status_code, 404)
        state = self.start()
        provider = self.app.extensions['nipap_oidc']['providers']['bio']
        with patch.object(provider, 'exchange') as exchange:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string=[('state', state), ('state', state), ('code', 'test')])
            self.assertEqual(response.status_code, 400)
            exchange.assert_not_called()

    def test_expiry_and_configuration_revocation(self):
        for expiry in [0, 'invalid', time.time() + 300]:
            with self.client.session_transaction(base_url=self.base) as current:
                current.update(user='reader', _oidc_provider='bio',
                               _oidc_sub='subject', _oidc_identity='subject', _oidc_exp=expiry)
            if isinstance(expiry, float):
                self.config['identities'].clear()
            current = self.client.get('/identity', base_url=self.base).get_json()
            self.assertNotIn('user', current)


class AppFactoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = configparser.ConfigParser()
        self.config.read_dict({'www': {'xmlrpc_uri': 'http://backend.example.test/',
                                       'secret_key': 'test-only'}})

    def make_app(self, overrides):
        with patch('nipap.nipapconfig.NipapConfig', return_value=self.config):
            return create_app(dict(TESTING=True, **overrides))

    def test_default_application_keeps_local_login_only(self):
        app = self.make_app({})
        self.assertNotIn('nipap_oidc', app.extensions)
        self.assertEqual(app.test_client().get('/auth/login').status_code, 200)
        self.assertEqual(app.test_client().get('/auth/oidc/primary/callback').status_code, 404)

    def test_private_file_enables_full_application_and_rejects_public_file(self):
        path = Path(self.directory.name) / 'oidc.json'
        config = dict(transaction_db=str(Path(self.directory.name) / 'state.db'),
                      providers={'primary': dict(
                          issuer='https://idp.example.test/',
                          authorization_endpoint='https://idp.example.test/authorize',
                          token_endpoint='https://idp.example.test/token',
                          jwks_uri='https://idp.example.test/jwks',
                          redirect_uri='https://ipam.example.test/auth/oidc/primary/callback',
                          client_id='example-client', client_secret='test-only',
                          identities={'subject': dict(username='reader', readonly=True)})})
        path.write_text(json.dumps(config))
        os.chmod(path, 0o600)
        app = self.make_app({'OIDC_CONFIG_FILE': str(path)})
        response = app.test_client().get('/auth/login', base_url='https://ipam.example.test')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'/auth/oidc/primary/login', response.data)
        os.chmod(path, 0o644)
        from nipap.nipapconfig import NipapConfigError
        with self.assertRaises(NipapConfigError):
            self.make_app({'OIDC_CONFIG_FILE': str(path)})


if __name__ == '__main__':
    unittest.main()
