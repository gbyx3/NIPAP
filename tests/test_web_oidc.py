"""Offline OIDC tests using real signatures and Flask session state."""
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
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from nipapwww.oidc import LoginRejected, Provider, local_return_path
    from nipapwww.oidc import init_app
except ModuleNotFoundError as error:
    if error.name not in ('authlib', 'jwt', 'cryptography', 'requests'):
        raise
    raise unittest.SkipTest('Install the nipap-www oidc extra to run OIDC tests')
from flask import Flask, session
import requests
from types import SimpleNamespace
from nipapwww import auth
from nipapwww import create_app


class ReturnPathTest(unittest.TestCase):
    def test_unsafe_redirects(self):
        for value in ['https://evil.test', '//evil.test', '/\\evil', '/\nevil',
                      ' /evil', None]:
            self.assertEqual(local_return_path(value), '/')
        self.assertEqual(local_return_path('/ng/prefix?q=x'), '/ng/prefix?q=x')


class ProviderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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
        encoded = jwt.encode(self.claims if claims is None else claims,
                             key or self.key, algorithm=algorithm)
        key = jwt.PyJWK.from_dict(json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())))
        with patch.object(self.provider.keys, 'get_signing_key_from_jwt', return_value=key):
            return self.provider.validate(encoded, 'test-nonce')

    def test_valid_identity_is_server_mapped_readonly(self):
        self.claims.update(readonly=False, username='admin')
        identity = self.validate()
        self.assertTrue(identity['readonly'])
        self.assertEqual(identity['username'], 'reader')

    def test_required_assurance_does_not_treat_one_as_true(self):
        self.config['identities']['immutable-subject']['required_claims']['assurance'] = {'certificate': True}
        with self.assertRaises(LoginRejected):
            self.validate(dict(self.claims, assurance={'certificate': 1}))
        self.validate(dict(self.claims, assurance={'certificate': True}))

    def test_explicit_immutable_directory_claim_and_resource_scopes(self):
        self.provider = Provider(dict(self.config, identity_claim='directory_id',
            identities={'directory-object': dict(username='reader', readonly=True)},
            scopes=['openid', 'https://resource.example.test/allatclaims']))
        with self.assertRaises(LoginRejected):
            self.validate()
        result = self.validate(dict(self.claims, directory_id='directory-object'))
        self.assertEqual(result['identity_key'], 'directory-object')
        self.assertEqual(result['subject'], self.claims['sub'])
        self.assertIn('https://resource.example.test/allatclaims', self.provider.scopes)

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
            self.validate(key=b'synthetic-hmac-secret-at-least-32-bytes', algorithm='HS256')
        with self.assertRaises(LoginRejected):
            self.provider.validate('not.a.token', 'test-nonce')

    def test_insecure_configuration_rejected(self):
        for key in ['issuer', 'token_endpoint', 'authorization_endpoint',
                    'jwks_uri', 'redirect_uri']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                Provider(dict(self.config, **{key: 'http://insecure.test'}))
        with self.assertRaises(ValueError):
            Provider(dict(self.config, algorithms=['HS256']))
        with self.assertRaises(ValueError):
            Provider(dict(self.config, ca_bundle=False))

    def test_signing_keys_use_pyjwt_cache_and_fixed_https_fetch(self):
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        key['kid'] = 'test-key'
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({'keys': [key]}).encode()
        response._content_consumed = True
        encoded = jwt.encode(self.claims, self.key, algorithm='RS256', headers={
            'kid': 'test-key', 'jku': 'https://untrusted.example.test/keys'})
        with patch.object(requests.Session, 'get', return_value=response) as fetch:
            self.provider.validate(encoded, 'test-nonce')
            self.provider.validate(encoded, 'test-nonce')
        fetch.assert_called_once_with(self.config['jwks_uri'], timeout=15,
                                      verify=True, allow_redirects=False, stream=True)

    def test_signing_key_fetch_rejects_redirects_and_oversized_responses(self):
        for status, body in [(302, b''), (200, b'x' * (1024 * 1024 + 1))]:
            response = requests.Response()
            response.status_code = status
            response._content = body
            response._content_consumed = True
            encoded = jwt.encode(self.claims, self.key, algorithm='RS256', headers={'kid': 'test-key'})
            with patch.object(requests.Session, 'get', return_value=response):
                with self.subTest(status=status), self.assertRaises(LoginRejected):
                    self.provider.validate(encoded, 'test-nonce')

    def test_provider_key_caches_are_separate(self):
        other = Provider(dict(self.config, jwks_uri='https://other.example.test/keys'))
        self.assertIsNot(other.keys, self.provider.keys)
        self.assertIsNot(other.keys.jwk_set_cache, self.provider.keys.jwk_set_cache)


class BrowserTest(unittest.TestCase):
    def setUp(self):
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
        init_app(self.app, dict(providers={'bio': self.config}))
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
        self.assertIn(b'role="switch"', response.data)
        self.assertIn(b'class="top_menu"', response.data)

    def test_existing_welcome_message_is_preserved_and_escaped(self):
        self.app.config.update(WELCOME_MESSAGE='<script>access notice</script>')
        response = self.client.get('/auth/login', base_url=self.base)
        self.assertIn(b'&lt;script&gt;access notice&lt;/script&gt;', response.data)
        self.assertNotIn(b'<script>access notice</script>', response.data)

    def csrf(self):
        with self.client.session_transaction(base_url=self.base) as current:
            return current['_csrf']

    def start(self):
        response = self.client.post('/auth/oidc/bio/login', base_url=self.base,
                                    data={'_csrf': self.csrf()})
        self.assertEqual(response.status_code, 302)
        return parse_qs(urlsplit(response.location).query)['state'][0]

    def oauth_client(self):
        return self.app.extensions['nipap_oidc']['oauth'].create_client('bio')

    def state_data(self, state):
        with self.client.session_transaction(base_url=self.base) as current:
            return self.oauth_client().framework.get_state_data(current, state)

    def test_authlib_session_holds_nonce_pkce_and_safe_return_path(self):
        with self.client.session_transaction(base_url=self.base) as current:
            current['path_before_login'] = '//evil.test/'
        state = self.start()
        data = self.state_data(state)
        query = parse_qs(urlsplit(data['url']).query)
        self.assertEqual(query['state'], [state])
        self.assertEqual(query['nonce'], [data['nonce']])
        self.assertEqual(query['code_challenge_method'], ['S256'])
        self.assertEqual(query['response_type'], ['code'])
        self.assertEqual(query['max_age'], ['300'])
        self.assertNotIn(data['code_verifier'], data['url'])
        with self.client.session_transaction(base_url=self.base) as current:
            self.assertEqual(current['_oidc_login']['return_path'], '/')
            self.assertLessEqual(current['_oidc_login']['expires'] - time.time(), 300)
            self.assertNotIn('client_secret', json.dumps(dict(current)))

    def test_new_attempt_replaces_previous_state_without_growing_cookie(self):
        previous = self.start()
        for _ in range(8):
            state = self.start()
            self.assertIsNone(self.state_data(previous))
            self.assertIsNotNone(self.state_data(state))
            cookie = self.client.get_cookie('session', domain='nipap.test')
            self.assertLess(len(cookie.value), 3800)
            previous = state

    def test_missing_browser_cookie_or_wrong_provider_rejects_before_exchange(self):
        state = self.start()
        extension = self.app.extensions['nipap_oidc']
        extension['providers']['other'] = Provider(self.config)
        with patch.object(self.oauth_client(), 'fetch_access_token') as exchange:
            response = self.app.test_client().get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 400)
            response = self.client.get('/auth/oidc/other/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 400)
            exchange.assert_not_called()

    def test_expired_state_is_cleared_without_exchange(self):
        state = self.start()
        with self.client.session_transaction(base_url=self.base) as current:
            current['_oidc_login'] = dict(current['_oidc_login'], expires=0)
        with patch.object(self.oauth_client(), 'fetch_access_token') as exchange:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 400)
            exchange.assert_not_called()
        self.assertIsNone(self.state_data(state))

    def test_missing_id_token_cannot_supply_an_unverified_identity(self):
        state = self.start()
        token = dict(access_token='synthetic-token', userinfo={'username': 'administrator'})
        with patch.object(self.oauth_client(), 'fetch_access_token', return_value=token):
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.state_data(state))
        with self.client.session_transaction(base_url=self.base) as current:
            self.assertNotIn('user', current)

    def test_exchange_failure_is_sanitized_and_discards_pending_state(self):
        state = self.start()
        with patch.object(self.oauth_client(), 'fetch_access_token', side_effect=ValueError('sensitive-value')):
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b'sensitive-value', response.data)
        self.assertIsNone(self.state_data(state))

    def test_provider_denial_clears_state_without_exchange(self):
        state = self.start()
        with patch.object(self.oauth_client(), 'fetch_access_token') as exchange:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'error': 'access_denied',
                              'error_description': 'sensitive-description'})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn(b'sensitive-description', response.data)
            exchange.assert_not_called()
        self.assertIsNone(self.state_data(state))

    def test_copied_cookie_relies_on_idp_rejecting_a_reused_code(self):
        state = self.start()
        cookie = self.client.get_cookie('session', domain='nipap.test').value
        identity = dict(username='reader', full_name='Reader', readonly=True,
                        subject='subject', identity_key='subject', expires=time.time() + 300)
        provider = self.app.extensions['nipap_oidc']['providers']['bio']
        token = dict(id_token='synthetic-id-token', access_token='synthetic-access-token')
        with patch.object(self.oauth_client(), 'fetch_access_token',
                          side_effect=[token, ValueError('authorization code already used')]) as exchange, \
             patch.object(provider, 'validate', return_value=identity):
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 302)
            self.client.set_cookie('session', cookie, domain='nipap.test')
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(exchange.call_count, 2)

    def test_cookie_signature_tampering_rejects_state(self):
        state = self.start()
        cookie = self.client.get_cookie('session', domain='nipap.test').value
        self.client.set_cookie('session', 'X' + cookie[1:], domain='nipap.test')
        with patch.object(self.oauth_client(), 'fetch_access_token') as exchange:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
            self.assertEqual(response.status_code, 400)
            exchange.assert_not_called()

    def test_full_callback_exchanges_session_pkce_and_verifies_signature(self):
        with self.client.session_transaction(base_url=self.base) as current:
            current['path_before_login'] = '/prefix?example=1'
        state = self.start()
        data = self.state_data(state)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        encoded = jwt.encode(dict(iss=self.config['issuer'], aud=self.config['client_id'],
                                  sub='subject', nonce=data['nonce'], iat=now,
                                  exp=now + 600, auth_time=now), key,
                             algorithm='RS256', headers={'kid': 'test-key'})
        calls = []
        def send(client, prepared, **kwargs):
            calls.append(prepared.url)
            self.assertFalse(client.trust_env)
            self.assertTrue(kwargs['verify'])
            self.assertFalse(kwargs['allow_redirects'])
            response = requests.Response()
            response.status_code = 200
            response._content_consumed = True
            if prepared.url == self.config['token_endpoint']:
                self.assertEqual(kwargs['timeout'], (5, 15))
                form = parse_qs(prepared.body)
                self.assertEqual(form['code_verifier'], [data['code_verifier']])
                self.assertEqual(form['redirect_uri'], [self.config['redirect_uri']])
                self.assertEqual(form['code'], ['test-code'])
                self.assertTrue(prepared.headers['Authorization'].startswith('Basic '))
                body = dict(access_token='synthetic-access-token', refresh_token='synthetic-refresh-token',
                            token_type='Bearer', id_token=encoded)
            elif prepared.url == self.config['jwks_uri']:
                self.assertEqual(kwargs['timeout'], 15)
                public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
                body = {'keys': [dict(public, kid='test-key')]}
            else:
                self.fail('Unexpected outbound request')
            response._content = json.dumps(body).encode()
            return response
        with patch.object(requests.Session, 'send', autospec=True, side_effect=send):
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'test-code'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/prefix?example=1')
        self.assertEqual(calls, [self.config['token_endpoint'], self.config['jwks_uri']])
        with self.client.session_transaction(base_url=self.base) as current:
            self.assertEqual(current['user'], 'reader')
            saved = json.dumps(dict(current))
            for secret in [encoded, 'synthetic-access-token', 'synthetic-refresh-token',
                           data['nonce'], data['code_verifier']]:
                self.assertNotIn(secret, saved)

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
        token = dict(id_token='synthetic-id-token', access_token='synthetic-access-token')
        with patch.object(self.oauth_client(), 'fetch_access_token', return_value=token) as exchange, \
             patch.object(provider, 'validate', return_value=identity) as validate:
            response = self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                                       query_string={'state': state, 'code': 'one-use-code'})
            self.assertEqual(response.status_code, 302)
            exchange.assert_called_once()
            validate.assert_called_once()
            self.assertEqual(self.client.get('/auth/oidc/bio/callback', base_url=self.base,
                query_string={'state': state, 'code': 'one-use-code'}).status_code, 400)
            exchange.assert_called_once()
        current = self.client.get('/identity', base_url=self.base).get_json()
        self.assertTrue(current['readonly'])
        self.assertEqual(current['authenticated_identity'], 'subject@oidc:bio')
        for forbidden in ['id_token', 'access_token', 'refresh_token', '_oidc_login']:
            self.assertNotIn(forbidden, current)
        self.assertFalse(any(key.startswith('_state_') for key in current))
        self.assertEqual(self.client.post('/write', base_url=self.base,
            headers={'X-XSRF-TOKEN': self.csrf()}).status_code, 403)

    def test_unknown_provider_and_duplicate_parameters(self):
        self.assertEqual(self.client.get('/auth/oidc/unknown/callback',
                                         base_url=self.base).status_code, 404)
        state = self.start()
        with patch.object(self.oauth_client(), 'fetch_access_token') as exchange:
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

    def test_identity_reload_precedes_shared_readonly_guard(self):
        with self.client.session_transaction(base_url=self.base) as current:
            current.update(user='reader', readonly=False, _oidc_provider='bio',
                           _oidc_identity='subject', _oidc_exp=time.time() + 300)
        response = self.client.post('/write', base_url=self.base,
                                    headers={'X-XSRF-TOKEN': self.csrf()})
        self.assertEqual(response.status_code, 403)


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
        self.assertNotIn('nipap_web_security', app.extensions)
        self.assertEqual(app.test_client().get('/auth/login').status_code, 200)
        self.assertEqual(app.test_client().get('/auth/oidc/primary/callback').status_code, 404)

    def test_legacy_local_login_retains_welcome_message(self):
        app = self.make_app({'WELCOME_MESSAGE': 'Example local welcome'})
        self.assertIn(b'Example local welcome', app.test_client().get('/auth/login').data)

    def test_oidc_extra_uses_the_backends_existing_requests_pin(self):
        import tomllib
        root = Path(__file__).resolve().parents[1]
        backend = tomllib.loads((root / 'nipap/pyproject.toml').read_text())
        web = tomllib.loads((root / 'nipap-www/pyproject.toml').read_text())
        requests_pin = next(d for d in backend['project']['dependencies'] if d.startswith('requests=='))
        self.assertIn(requests_pin, web['project']['optional-dependencies']['oidc'])
        self.assertFalse(any(dependency.lower().startswith('joserfc')
                             for dependency in web['project']['optional-dependencies']['oidc']))

    def test_private_file_enables_full_application_and_rejects_public_file(self):
        path = Path(self.directory.name) / 'oidc.json'
        config = dict(providers={'primary': dict(
                          issuer='https://idp.example.test/',
                          authorization_endpoint='https://idp.example.test/authorize',
                          token_endpoint='https://idp.example.test/token',
                          jwks_uri='https://idp.example.test/jwks',
                          redirect_uri='https://ipam.example.test/auth/oidc/primary/callback',
                          client_id='example-client', client_secret='test-only',
                          identities={'subject': dict(username='reader', readonly=True)})})
        path.write_text(json.dumps(config))
        os.chmod(path, 0o600)
        app = self.make_app({'OIDC_CONFIG_FILE': str(path), 'WEB_SECURITY_ENABLED': False})
        self.assertTrue(app.extensions['nipap_web_security'])
        response = app.test_client().get('/auth/login', base_url='https://ipam.example.test')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'/auth/oidc/primary/login', response.data)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [path])
        os.chmod(path, 0o644)
        from nipap.nipapconfig import NipapConfigError
        with self.assertRaises(NipapConfigError):
            self.make_app({'OIDC_CONFIG_FILE': str(path)})


if __name__ == '__main__':
    unittest.main()
