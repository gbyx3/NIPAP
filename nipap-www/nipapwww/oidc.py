"""Optional browser OIDC login."""
import json
import math
from urllib.parse import urlsplit
import time

from authlib.integrations.flask_client import OAuth, FlaskOAuth2App
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


class BrowserClient(FlaskOAuth2App):
    def parse_id_token(self, token, nonce, **kwargs):
        provider = current_app.extensions['nipap_oidc']['providers'][self.name]
        return provider.validate(token.get('id_token'), nonce)


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
        for name, default in [('max_age', 300), ('session_ttl', 900)]:
            value = self.config.get(name, default)
            if type(value) is not int or not 1 <= value <= 3600:
                raise ValueError('OIDC time limits must be integers from 1 to 3600 seconds')
        self.keys = SigningKeys(self.config['jwks_uri'], self.config.get('ca_bundle', True))

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


bp = Blueprint('oidc', __name__, url_prefix='/auth/oidc')


def init_app(app, config):
    """Register before the application blueprints."""
    if not config.get('providers'):
        raise ValueError('OIDC requires at least one provider')
    providers = {name: Provider(value) for name, value in config['providers'].items()}
    if any(not name or not all(c.isalnum() or c in '-_' for c in name)
           for name in providers):
        raise ValueError('Invalid OIDC provider name')
    oauth = OAuth(app)
    for name, provider in providers.items():
        settings = provider.config
        client = oauth.register(
            name, client_cls=BrowserClient, client_id=settings['client_id'],
            client_secret=settings['client_secret'],
            authorize_url=settings['authorization_endpoint'],
            access_token_url=settings['token_endpoint'],
            client_kwargs=dict(scope=' '.join(provider.scopes),
                               token_endpoint_auth_method='client_secret_basic',
                               code_challenge_method='S256', default_timeout=(5, 15),
                               trust_env=False, verify=settings.get('ca_bundle', True)))
        client.framework.expires_in = 300
    app.extensions['nipap_oidc'] = dict(providers=providers, oauth=oauth)
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
    previous = session.pop('_oidc_login', None)
    if previous and previous['provider'] in extension['providers']:
        old_client = extension['oauth'].create_client(previous['provider'])
        old_client.framework.clear_state_data(session, previous['state'])
    client = extension['oauth'].create_client(provider_name)
    authorization = client.create_authorization_url(
        provider.config['redirect_uri'], max_age=provider.config.get('max_age', 300))
    client.save_authorize_data(redirect_uri=provider.config['redirect_uri'], **authorization)
    session['_oidc_login'] = dict(provider=provider_name, state=authorization['state'],
                                 expires=time.time() + 300,
                                 return_path=local_return_path(session.get('path_before_login', '/')))
    return redirect(authorization['url'])


@bp.route('/<provider_name>/callback')
def callback(provider_name):
    extension = current_app.extensions['nipap_oidc']
    provider = extension['providers'].get(provider_name)
    if provider is None:
        abort(404)
    try:
        state, code = request.args.get('state'), request.args.get('code')
        if (len(request.args.getlist('state')) != 1
                or len(request.args.getlist('code')) > 1 or not state):
            raise LoginRejected('Invalid callback parameters')
        if 'error' not in request.args and (not code or len(code) > 8192):
            raise LoginRejected('Invalid authorization code')
        pending = session.get('_oidc_login')
        if (not pending or pending['provider'] != provider_name
                or pending['state'] != state):
            raise LoginRejected('Invalid login state')
        session.pop('_oidc_login')
        client = extension['oauth'].create_client(provider_name)
        try:
            # Authlib's session lookup does not enforce expiry.
            if pending['expires'] <= time.time():
                raise LoginRejected('Login expired')
            token = client.authorize_access_token(allow_redirects=False)
            if not token.get('id_token'):
                raise LoginRejected('Missing ID token')
            identity = token['userinfo']
        finally:
            client.framework.clear_state_data(session, pending['state'])
    except Exception:
        # Provider errors can contain tokens.
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
    return redirect(local_return_path(pending['return_path']))
