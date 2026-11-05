"""Shared JWT and real HTTP-auth dispatch regressions; no live services."""
import configparser
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from werkzeug.datastructures import Authorization
from werkzeug.exceptions import HTTPException

from nipap.authlib import AuthError, AuthFactory, JwtAuth
from nipap.jwt_auth import JwtValidationError, JwtVerifier


class SignedTokenFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.public['kid'] = 'one'

    def setUp(self):
        self.now = int(time.time())
        self.claims = dict(iss='https://issuer.example.test/',
                           aud='https://api.example.test/', sub='immutable-subject',
                           iat=self.now, exp=self.now + 600, auth_time=self.now,
                           directory_id='immutable-directory-id',
                           authn='certificate', groups=['readers'])
        self.verifier = JwtVerifier(self.claims['iss'], self.claims['aud'],
                                    'https://issuer.example.test/jwks', ['RS256'],
                                    required_claims={'authn': 'certificate'}, max_age=300)

    def encode(self, claims=None, key=None, algorithm='RS256', headers=None):
        return jwt.encode(self.claims if claims is None else claims, key or self.key,
                          algorithm=algorithm, headers={'kid': 'one', **(headers or {})})

    def validate(self, claims=None, **kwargs):
        return self.verifier.validate(self.encode(claims), keys=[self.public], **kwargs)


class JwtVerifierTest(SignedTokenFixture):
    def test_valid_certificate_assurance_and_identity(self):
        self.assertEqual(self.validate()['sub'], 'immutable-subject')

    def test_assurance_checks_are_json_exact_not_boolean_numeric_equivalence(self):
        self.verifier.required_claims = {'assurance': {'certificate': True}}
        with self.assertRaises(JwtValidationError):
            self.validate(dict(self.claims, assurance={'certificate': 1}))
        self.validate(dict(self.claims, assurance={'certificate': True}))

    def test_wrong_or_missing_required_claims(self):
        for name in ['iss', 'aud', 'sub', 'exp', 'iat', 'auth_time', 'authn']:
            value = dict(self.claims)
            del value[name]
            with self.subTest(missing=name), self.assertRaises(JwtValidationError):
                self.validate(value)
        for name, value in [('iss', 'https://other.example.test/'),
                            ('aud', 'web-client-not-api'), ('exp', self.now - 60),
                            ('iat', self.now + 600), ('auth_time', self.now - 600),
                            ('authn', 'password'), ('iat', True), ('exp', '9999999999'),
                            ('auth_time', float('nan'))]:
            with self.subTest(claim=name, value=value), self.assertRaises(JwtValidationError):
                self.validate(dict(self.claims, **{name: value}))

    def test_oidc_profile_adds_nonce_and_authorized_party_checks(self):
        with self.assertRaises(JwtValidationError):
            self.validate(oidc=True, nonce='expected')
        claims = dict(self.claims, nonce='expected', aud=[self.claims['aud'], 'other'])
        with self.assertRaises(JwtValidationError):
            self.validate(claims, oidc=True, nonce='expected')
        self.validate(dict(claims, azp=self.claims['aud']), oidc=True, nonce='expected')

    def test_hmac_rejected_before_key_fetch_and_invalid_signature_rejected(self):
        with patch.object(self.verifier, 'public_keys') as fetch:
            with self.assertRaises(JwtValidationError):
                self.verifier.validate(self.encode(key=b'synthetic-secret-at-least-32-bytes', algorithm='HS256'))
            fetch.assert_not_called()
        with self.assertRaises(JwtValidationError):
            self.verifier.validate(self.encode(key=self.other), keys=[self.public])

    def test_ambiguous_unknown_private_and_non_signing_keys_rejected(self):
        for keys in [[], [self.public, self.public], [dict(self.public, kid='other')],
                     [dict(self.public, use='enc')], [dict(self.public, d='private')],
                     [dict(self.public, alg='HS256')], [dict(self.public, key_ops=['encrypt'])]]:
            with self.subTest(keys=len(keys)), self.assertRaises(JwtValidationError):
                self.verifier.validate(self.encode(), keys=keys)

    def test_jwks_requests_are_fixed_bounded_and_tls_verified(self):
        response = Mock(status_code=200)
        response.iter_content.return_value = [json.dumps({'keys': [self.public]}).encode()]
        client = Mock()
        client.get.return_value.__enter__ = Mock(return_value=response)
        client.get.return_value.__exit__ = Mock(return_value=False)
        with patch('nipap.jwt_auth.requests.Session') as factory:
            factory.return_value.__enter__.return_value = client
            self.verifier.validate(self.encode(headers={'jku': 'https://untrusted.example.test/keys'}))
        client.get.assert_called_once_with('https://issuer.example.test/jwks',
                                           timeout=(5, 15), verify=True,
                                           allow_redirects=False, stream=True)
        self.assertFalse(client.trust_env)

    def test_redirects_and_oversized_jwks_fail_without_raw_error(self):
        for status, chunks in [(302, []), (200, [b'x' * (1024 * 1024 + 1)])]:
            response = Mock(status_code=status)
            response.iter_content.return_value = chunks
            with patch('nipap.jwt_auth.requests.Session') as factory:
                factory.return_value.__enter__.return_value.get.return_value.__enter__.return_value = response
                with self.assertRaises(JwtValidationError) as error:
                    self.verifier.public_keys()
                self.assertNotIn('x' * 10, str(error.exception))

    def test_insecure_configuration_fails_closed(self):
        for changes in [{'issuer': 'http://issuer.example.test/'},
                        {'jwks_uri': 'http://issuer.example.test/jwks'},
                        {'audience': ''}, {'algorithms': ['HS256']}, {'ca_bundle': False}]:
            config = dict(issuer=self.claims['iss'], audience=self.claims['aud'],
                          jwks_uri='https://issuer.example.test/jwks', algorithms=['RS256'])
            config.update(changes)
            with self.subTest(config=changes), self.assertRaises(ValueError):
                JwtVerifier(**config)


class JwtBackendTest(SignedTokenFixture):
    def setUp(self):
        super().setUp()
        self.config = configparser.ConfigParser()
        self.config.read_dict({'auth.backends.jwt': {
            'type': 'JwtAuth', 'issuer': self.claims['iss'], 'audience': self.claims['aud'],
            'jwk_url': 'https://issuer.example.test/jwks', 'algorithms': 'RS256',
            'ro_group': 'readers', 'rw_group': 'writers', 'group_claim_name': 'groups',
            'required_claims': '{"authn": "certificate"}', 'max_age': '300',
            'identity_claim': 'directory_id', 'allowed_identities': '["immutable-directory-id"]'}})
        self.patch_config = patch('nipap.authlib.NipapConfig', return_value=self.config)
        self.patch_config.start()
        self.addCleanup(self.patch_config.stop)
        self.patch_keys = patch.object(JwtVerifier, 'public_keys', return_value=[self.public])
        self.patch_keys.start()
        self.addCleanup(self.patch_keys.stop)

    def backend(self, claims=None):
        return JwtAuth('jwt', self.encode(claims), 'test', {'readonly': False})

    def test_identity_only_set_after_verification_and_readonly_cannot_be_overridden(self):
        auth = self.backend()
        self.assertIsNone(auth.username)
        self.assertTrue(auth.authenticate())
        self.assertEqual(auth.username, 'immutable-directory-id')
        self.assertTrue(auth.readonly)
        self.assertFalse(auth.trusted)

    def test_unlisted_identity_or_missing_groups_denied(self):
        for claims in [dict(self.claims, directory_id='other'),
                       dict(self.claims, groups=[]), dict(self.claims, groups=[{}])]:
            auth = self.backend(claims)
            self.assertFalse(auth.authenticate())
            self.assertIsNone(auth.username)

    def test_readonly_precedence_and_readwrite_group(self):
        auth = self.backend(dict(self.claims, groups=['readers', 'writers']))
        self.assertTrue(auth.authenticate())
        self.assertTrue(auth.readonly)
        auth = self.backend(dict(self.claims, groups=['writers']))
        self.assertTrue(auth.authenticate())
        self.assertFalse(auth.readonly)

    def test_reused_instance_revalidates_and_clears_previous_identity(self):
        auth = self.backend()
        self.assertTrue(auth.authenticate())
        with patch.object(auth._verifier, 'validate', side_effect=JwtValidationError('rejected')):
            with self.assertRaises(AuthError):
                auth.authenticate()
        self.assertIsNone(auth.username)
        self.assertFalse(auth._authenticated)

    def test_missing_pins_fail_configuration_instead_of_accepting_legacy_defaults(self):
        for key in ['issuer', 'audience', 'algorithms']:
            value = self.config['auth.backends.jwt'].pop(key)
            with self.subTest(key=key), self.assertRaises(AuthError):
                self.backend()
            self.config['auth.backends.jwt'][key] = value

    def test_backend_keys_are_not_shared_between_configurations(self):
        first = self.backend()
        self.config['auth.backends.jwt']['jwk_url'] = 'https://other.example.test/jwks'
        second = self.backend()
        self.assertEqual(first._verifier.jwks_uri, 'https://issuer.example.test/jwks')
        self.assertEqual(second._verifier.jwks_uri, 'https://other.example.test/jwks')

    def test_real_api_decorators_dispatch_parsed_bearer(self):
        from nipap import nipap_xmlrpc, rest
        app = Flask(__name__)
        headers = {'Authorization': 'Bearer ' + self.encode(),
                   'NIPAP-Authoritative-Source': 'test'}
        receiver = SimpleNamespace(logger=Mock())
        def operation(self, args):
            return args['auth'].readonly
        with app.test_request_context('/test', headers=headers):
            result = nipap_xmlrpc.requires_auth(operation)(receiver, {'auth': {'authoritative_source': 'test'}})
            self.assertTrue(result)
        with app.test_request_context('/test', headers=headers):
            self.assertTrue(rest.requires_auth(operation)(receiver))

    def test_real_api_decorators_reject_malformed_or_invalid_bearer(self):
        from nipap import nipap_xmlrpc, rest
        app = Flask(__name__)
        receiver = SimpleNamespace(logger=Mock())
        operation = Mock()
        for header in ['Bearer', 'Bearer invalid', 'Digest username=test']:
            headers = {'Authorization': header, 'NIPAP-Authoritative-Source': 'test'}
            with app.test_request_context('/test', headers=headers):
                with self.assertRaises(nipap_xmlrpc.Fault):
                    nipap_xmlrpc.requires_auth(operation)(receiver, {'auth': {'authoritative_source': 'test'}})
            with app.test_request_context('/test', headers=headers):
                with self.assertRaises(HTTPException) as error:
                    rest.requires_auth(operation)(receiver)
                self.assertEqual(error.exception.get_response().status_code, 401)
                if header.startswith('Bearer'):
                    self.assertEqual(error.exception.get_response().headers['WWW-Authenticate'], 'Bearer')
        operation.assert_not_called()

    def test_real_api_decorators_preserve_basic_backend_selection(self):
        from nipap import nipap_xmlrpc, rest
        app = Flask(__name__)
        basic = Authorization('basic', {'username': 'reader@directory', 'password': 'test-only'})
        headers = {'Authorization': basic.to_header(), 'NIPAP-Authoritative-Source': 'test'}
        receiver = SimpleNamespace(logger=Mock())
        account = SimpleNamespace(authenticate=lambda: True, readonly=False)
        def operation(self, args):
            return args['auth'].readonly
        with patch.object(AuthFactory, 'get_auth', return_value=account) as select:
            with app.test_request_context('/test', headers=headers):
                self.assertFalse(nipap_xmlrpc.requires_auth(operation)(receiver, {'auth': {'authoritative_source': 'test'}}))
            with app.test_request_context('/test', headers=headers):
                self.assertFalse(rest.requires_auth(operation)(receiver))
            self.assertEqual(select.call_count, 2)
            for call in select.call_args_list:
                self.assertEqual(call.args[:2], ('reader@directory', 'test-only'))


class HttpDispatchTest(unittest.TestCase):
    def test_basic_backend_suffix_is_preserved(self):
        factory = object.__new__(AuthFactory)
        factory.get_auth = Mock(return_value='selected')
        authorization = Authorization('basic', {'username': 'reader@directory', 'password': 'test-only'})
        self.assertEqual(factory.get_auth_http(authorization, 'test'), 'selected')
        factory.get_auth.assert_called_once_with('reader@directory', 'test-only', 'test', None)

    def test_bearer_object_is_not_mistaken_for_basic(self):
        factory = object.__new__(AuthFactory)
        factory.get_auth_bearer_token = Mock(return_value='selected')
        factory.get_auth = Mock()
        value = Authorization.from_header('Bearer synthetic-token')
        self.assertEqual(factory.get_auth_http(value, 'test'), 'selected')
        factory.get_auth_bearer_token.assert_called_once_with('synthetic-token', 'test', None)
        factory.get_auth.assert_not_called()
