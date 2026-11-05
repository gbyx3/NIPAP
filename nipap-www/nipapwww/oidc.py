"""Optional browser OIDC login."""
import hashlib
from contextlib import contextmanager
import hmac
import json
import math
import os
from pathlib import Path
from urllib.parse import urlsplit
import secrets
import sqlite3
import time

from authlib.integrations.requests_client import OAuth2Session
import jwt
import requests
from flask import Blueprint, abort, current_app, g, redirect, request, session, url_for
from .web_security import init_app as init_web_security, local_return_path


class LoginRejected(ValueError):
    """A safe error message for a rejected login."""


def https_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError('OIDC requires HTTPS URLs without credentials')
    return value


def claim_matches(claims, name, expected):
    return name in claims and json.dumps(claims[name], sort_keys=True, allow_nan=False) == json.dumps(
        expected, sort_keys=True, allow_nan=False)


class SigningKeys(jwt.PyJWKClient):
    """Keep PyJWT's key selection and cache; bound the HTTPS fetch."""

    def __init__(self, uri, ca_bundle=True):
        super().__init__(https_url(uri), timeout=15)
        if ca_bundle is not True and (not isinstance(ca_bundle, str) or not ca_bundle):
            raise ValueError('OIDC TLS verification cannot be disabled')
        self.ca_bundle = ca_bundle

    def fetch_data(self):
        with requests.Session() as client:
            client.trust_env = False
            with client.get(self.uri, timeout=self.timeout, verify=self.ca_bundle,
                            allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise jwt.PyJWKClientError('Unable to fetch signing keys')
                chunks, size = [], 0
                for chunk in response.iter_content(8192):
                    size += len(chunk)
                    if size > 1024 * 1024:
                        raise jwt.PyJWKClientError('Signing key response too large')
                    chunks.append(chunk)
        return json.loads(b''.join(chunks))


class Transactions:
    """One-use login state shared by workers on the same host."""

    def __init__(self, path, capacity=1000, ttl=300):
        self.path = Path(path)
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError('OIDC state directory must be private and service-owned')
        if self.path.is_symlink():
            raise ValueError('OIDC state database must not be a symlink')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            stat = os.fstat(fd)
            if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                raise ValueError('OIDC state database must be private and service-owned')
        finally:
            os.close(fd)
        self.capacity, self.ttl = capacity, ttl
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS transactions '
                       '(state TEXT PRIMARY KEY, binding TEXT NOT NULL, '
                       'provider TEXT NOT NULL, expires INTEGER NOT NULL, '
                       'data TEXT NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def create(self, provider, binding, return_path='/'):
        state = secrets.token_urlsafe(32)
        data = dict(nonce=secrets.token_urlsafe(32),
                    verifier=secrets.token_urlsafe(48),
                    return_path=local_return_path(return_path))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM transactions WHERE expires <= ?', (int(time.time()),))
            if db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0] >= self.capacity:
                raise LoginRejected('Login capacity reached')
            db.execute('INSERT INTO transactions VALUES (?, ?, ?, ?, ?)',
                       (self.digest(state), self.digest(binding), provider,
                        int(time.time()) + self.ttl, json.dumps(data)))
        return state, data

    def consume(self, state, provider, binding):
        if not state or not binding or len(state) > 256:
            raise LoginRejected('Invalid login transaction')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT binding, provider, expires, data FROM transactions '
                             'WHERE state = ?', (self.digest(state),)).fetchone()
            if (not row or not hmac.compare_digest(row[0], self.digest(binding))
                    or row[1] != provider or row[2] <= time.time()):
                raise LoginRejected('Invalid login transaction')
            db.execute('DELETE FROM transactions WHERE state = ?', (self.digest(state),))
        return json.loads(row[3])


class Provider:
    """A configured OIDC provider and its allowed identities."""

    def __init__(self, config):
        self.config = dict(config)
        for key in ('issuer', 'authorization_endpoint', 'token_endpoint',
                    'jwks_uri', 'redirect_uri'):
            https_url(self.config[key])
        self.algorithms = self.config.get('algorithms', ['RS256'])
        if not self.algorithms or set(self.algorithms) - {'RS256', 'PS256', 'ES256'}:
            raise ValueError('Unsupported OIDC signing algorithm')
        if not self.config.get('client_id') or not self.config.get('client_secret'):
            raise ValueError('OIDC requires a confidential client')
        if not self.config.get('identities'):
            raise ValueError('OIDC requires explicit immutable identity mappings')
        self.identity_claim = self.config.get('identity_claim', 'sub')
        if not isinstance(self.identity_claim, str) or not self.identity_claim:
            raise ValueError('OIDC identity claim must be explicitly named')
        self.scopes = self.config.get('scopes', ['openid'])
        if (not isinstance(self.scopes, list) or 'openid' not in self.scopes
                or any(not isinstance(value, str) or not value or ' ' in value
                       for value in self.scopes)):
            raise ValueError('OIDC scopes must include openid')
        for subject, identity in self.config['identities'].items():
            if (not isinstance(subject, str) or not subject
                    or not identity.get('username')
                    or type(identity.get('readonly')) is not bool):
                raise ValueError('Invalid OIDC identity mapping')
        self.timeout = (5, 15)
        for name, default in [('max_age', 300), ('session_ttl', 900)]:
            value = self.config.get(name, default)
            if type(value) is not int or not 1 <= value <= 3600:
                raise ValueError('OIDC time limits must be integers from 1 to 3600 seconds')
        self.keys = SigningKeys(self.config['jwks_uri'], self.config.get('ca_bundle', True))

    def client(self):
        client = OAuth2Session(
            self.config['client_id'], self.config['client_secret'],
            scope=' '.join(self.scopes), redirect_uri=self.config['redirect_uri'],
            token_endpoint_auth_method='client_secret_basic',
            code_challenge_method='S256', default_timeout=self.timeout)
        client.trust_env = False
        client.verify = self.config.get('ca_bundle', True)
        if not client.verify:
            raise ValueError('OIDC TLS verification cannot be disabled')
        return client

    def authorization_url(self, state, transaction):
        with self.client() as client:
            url, _ = client.create_authorization_url(
                self.config['authorization_endpoint'], state=state,
                nonce=transaction['nonce'], code_verifier=transaction['verifier'],
                max_age=self.config.get('max_age', 300))
            return url

    def validate(self, encoded, nonce):
        try:
            if not isinstance(encoded, str) or not encoded or len(encoded) > 65536:
                raise LoginRejected('Invalid ID token')
            header = jwt.get_unverified_header(encoded)
            if header.get('alg') not in self.algorithms or 'crit' in header:
                raise LoginRejected('Unsupported ID token algorithm or header')
            key = self.keys.get_signing_key_from_jwt(encoded)
            claims = jwt.decode(encoded, key=key, algorithms=self.algorithms,
                                issuer=self.config['issuer'], audience=self.config['client_id'],
                                leeway=30, options={'require': ['iss', 'aud', 'sub', 'exp',
                                                               'iat', 'auth_time', 'nonce']})
            now = int(time.time())
            if not isinstance(claims['sub'], str) or not claims['sub']:
                raise LoginRejected('Missing subject')
            if not isinstance(nonce, str) or not nonce or claims['nonce'] != nonce:
                raise LoginRejected('Invalid login nonce')
            audience = claims['aud']
            if (isinstance(audience, list) and len(audience) > 1
                    and claims.get('azp') != self.config['client_id']):
                raise LoginRejected('Invalid authorized party')
            if 'azp' in claims and claims['azp'] != self.config['client_id']:
                raise LoginRejected('Invalid authorized party')
            for name in ('iat', 'exp', 'auth_time'):
                if type(claims[name]) not in (int, float) or not math.isfinite(claims[name]):
                    raise LoginRejected('Invalid token time')
            if (claims['auth_time'] > now + 30
                    or now - claims['auth_time'] > self.config.get('max_age', 300) + 30):
                raise LoginRejected('Fresh authentication required')
            identity_key = claims.get(self.identity_claim)
            if not isinstance(identity_key, str) or not identity_key:
                raise LoginRejected('Missing immutable identity claim')
            identity = self.config['identities'].get(identity_key)
            if identity is None:
                raise LoginRejected('Identity not authorized')
            for key, value in identity.get('required_claims', {}).items():
                if not claim_matches(claims, key, value):
                    raise LoginRejected('Required identity assurance missing')
            return dict(username=identity['username'],
                        full_name=identity.get('full_name', identity['username']),
                        readonly=identity['readonly'], subject=claims['sub'],
                        identity_key=identity_key,
                        expires=min(claims['exp'], now + self.config.get('session_ttl', 900)))
        except (jwt.PyJWTError, requests.RequestException, ValueError, TypeError, KeyError, OverflowError):
            raise LoginRejected('ID token rejected') from None

    def exchange(self, code, transaction):
        try:
            if not isinstance(code, str) or not code or len(code) > 8192:
                raise LoginRejected('Invalid authorization code')
            with self.client() as client:
                token = client.fetch_token(
                    self.config['token_endpoint'], grant_type='authorization_code',
                    code=code, code_verifier=transaction['verifier'],
                    allow_redirects=False)
                return self.validate(token.get('id_token'), transaction['nonce'])
        except Exception:
            # Provider errors can contain tokens.
            raise LoginRejected('OIDC login rejected') from None


bp = Blueprint('oidc', __name__, url_prefix='/auth/oidc')


def init_app(app, config):
    """Register before the application blueprints."""
    if not config.get('providers'):
        raise ValueError('OIDC requires at least one provider')
    providers = {name: Provider(value) for name, value in config['providers'].items()}
    if any(not name or not all(c.isalnum() or c in '-_' for c in name)
           for name in providers):
        raise ValueError('Invalid OIDC provider name')
    store = Transactions(config['transaction_db'])
    app.extensions['nipap_oidc'] = dict(providers=providers, store=store)
    app.register_blueprint(bp)

    @app.context_processor
    def login_options():
        return dict(oidc_providers={name: provider.config.get('label', name)
                                   for name, provider in providers.items()})

    @app.before_request
    def external_identity():
        # Must execute before audit authorization and pynipap options are set.
        g.oidc_enabled = True
        if '_oidc_provider' in session:
            provider = providers.get(session['_oidc_provider'])
            identity = (provider.config['identities'].get(session.get('_oidc_identity'))
                        if provider else None)
            expiry = session.get('_oidc_exp')
            if (identity is None or type(expiry) not in (int, float)
                    or not math.isfinite(expiry)
                    or expiry <= time.time()):
                session.clear()
            else:
                session['user'] = identity['username']
                session['readonly'] = identity['readonly']
                session['full_name'] = identity.get('full_name', identity['username'])

    # Reload the identity before checking read-only access.
    init_web_security(app)


@bp.route('/<provider_name>/login', methods=['POST'])
def begin(provider_name):
    extension = current_app.extensions['nipap_oidc']
    provider = extension['providers'].get(provider_name)
    if provider is None:
        abort(404)
    binding = session.setdefault('_oidc_binding', secrets.token_urlsafe(32))
    try:
        state, transaction = extension['store'].create(
            provider_name, binding, session.get('path_before_login', '/'))
        return redirect(provider.authorization_url(state, transaction))
    except LoginRejected:
        abort(503, description='Login is temporarily unavailable')


@bp.route('/<provider_name>/callback')
def callback(provider_name):
    extension = current_app.extensions['nipap_oidc']
    provider = extension['providers'].get(provider_name)
    if provider is None:
        abort(404)
    try:
        # Reject duplicate parameters rather than selecting an ambiguous value.
        if any(len(request.args.getlist(key)) != 1 for key in ('state', 'code')):
            raise LoginRejected('Invalid callback parameters')
        if 'error' in request.args:
            raise LoginRejected('Provider rejected login')
        transaction = extension['store'].consume(
            request.args['state'], provider_name, session.get('_oidc_binding', ''))
        identity = provider.exchange(request.args['code'], transaction)
    except LoginRejected:
        abort(400, description='SSO login rejected. Start a new login.')
    session.clear()
    session.update(user=identity['username'], full_name=identity['full_name'],
                   readonly=identity['readonly'], current_vrfs={},
                   authenticated_identity='{}@oidc:{}'.format(identity['subject'], provider_name),
                   _oidc_provider=provider_name, _oidc_sub=identity['subject'],
                   _oidc_identity=identity['identity_key'],
                   _oidc_exp=identity['expires'])
    session.permanent = True
    current_app.logger.info('OIDC login accepted provider=%s user=%s readonly=%s',
                            provider_name, identity['username'], identity['readonly'])
    return redirect(local_return_path(transaction['return_path']))
