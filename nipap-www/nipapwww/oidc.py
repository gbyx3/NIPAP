"""Opt-in OIDC primitives. No identity headers or backend JWT authentication.

Configuration and credentials must be supplied by the administrator, not tokens.
"""
import hashlib
from contextlib import contextmanager
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import time

from authlib.integrations.requests_client import OAuth2Session
from flask import Blueprint, abort, current_app, g, redirect, request, session, url_for
from nipap.jwt_auth import JwtVerifier, claim_matches, https_url
from .web_security import init_app as init_web_security, local_return_path


class LoginRejected(ValueError):
    """A login could not be authenticated or authorized. Never include tokens."""


class Transactions:
    """Bounded, atomic, one-use transactions shared by synchronous workers.

    Store in a dedicated local directory owned by the web service, mode 0700.
    The database contains short-lived PKCE verifiers; never publish or log it.
    """

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
    """Strict confidential authorization-code client with explicit endpoints.

    Administrators pin issuer/endpoints independently for each provider. Avoid
    dynamic discovery and redirects at login: no token-supplied URLs are fetched.
    Identities are keyed by exact subject; additional claims are exact matches.
    """

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
        self.verifier = JwtVerifier(
            issuer=self.config['issuer'], audience=self.config['client_id'],
            jwks_uri=self.config['jwks_uri'], algorithms=self.algorithms,
            ca_bundle=self.config.get('ca_bundle', True),
            max_age=self.config.get('max_age', 300))

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

    def public_keys(self):
        return self.verifier.public_keys()

    def validate(self, encoded, nonce, keys):
        try:
            claims = self.verifier.validate(encoded, keys=keys, nonce=nonce, oidc=True)
            now = int(time.time())
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
        except Exception:
            # Cryptographic/library exceptions may embed claims or token data.
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
                return self.validate(token.get('id_token'), transaction['nonce'],
                                     self.public_keys())
        except Exception:
            raise LoginRejected('OIDC login rejected') from None


bp = Blueprint('oidc', __name__, url_prefix='/auth/oidc')


def init_app(app, config):
    """Enable OIDC explicitly; call before registering other blueprints.

    Config is administrator-owned, never request-supplied. SQLite storage must
    live on local disk shared by all workers of this single web deployment.
    """
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

    # Validate/reload the external identity before shared read-only enforcement.
    # This is mandatory even if WEB_SECURITY_ENABLED was explicitly set false.
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
