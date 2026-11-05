"""Shared JWT verification for API access tokens and browser OIDC ID tokens.

Callers select the token purpose and audience; an ID token is not an API token.
All endpoints, algorithms and authorization requirements are administrator-owned.
"""
import math
import json
import time
from urllib.parse import urlsplit

import jwt
import requests


class JwtValidationError(ValueError):
    """Sanitized failure: never include a token, key or provider response."""


def claim_matches(claims, name, expected):
    # JSON-exact comparison avoids treating true as 1, including nested values.
    return name in claims and json.dumps(claims[name], sort_keys=True, allow_nan=False) == json.dumps(
        expected, sort_keys=True, allow_nan=False)


def https_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError('JWT endpoints require HTTPS without user information')
    return value


class JwtVerifier:
    def __init__(self, issuer, audience, jwks_uri, algorithms, ca_bundle=True,
                 required_claims=None, max_age=None):
        self.issuer = https_url(issuer)
        self.jwks_uri = https_url(jwks_uri)
        if not isinstance(audience, str) or not audience:
            raise ValueError('JWT requires an explicit audience')
        if (not isinstance(algorithms, list) or not algorithms
                or any(alg not in ('RS256', 'PS256', 'ES256') for alg in algorithms)):
            raise ValueError('JWT requires explicit asymmetric algorithms')
        if ca_bundle is not True and (not isinstance(ca_bundle, str) or not ca_bundle):
            raise ValueError('JWT TLS verification cannot be disabled')
        if required_claims is not None and not isinstance(required_claims, dict):
            raise ValueError('JWT required claims must be a mapping')
        if max_age is not None and (type(max_age) is not int or not 1 <= max_age <= 3600):
            raise ValueError('JWT max_age must be from 1 to 3600 seconds')
        self.audience, self.algorithms = audience, list(algorithms)
        self.ca_bundle = ca_bundle
        self.required_claims = dict(required_claims or {})
        self.max_age = max_age
        self.timeout = (5, 15)

    def public_keys(self):
        try:
            with requests.Session() as client:
                client.trust_env = False
                with client.get(self.jwks_uri, timeout=self.timeout,
                                verify=self.ca_bundle, allow_redirects=False,
                                stream=True) as response:
                    if response.status_code != 200:
                        raise JwtValidationError('Unable to obtain JWT signing keys')
                    chunks, size = [], 0
                    for chunk in response.iter_content(8192):
                        size += len(chunk)
                        if size > 1024 * 1024:
                            raise JwtValidationError('JWT signing key response too large')
                        chunks.append(chunk)
            data = json.loads(b''.join(chunks))
            if not isinstance(data.get('keys'), list):
                raise JwtValidationError('Invalid JWT signing keys')
            return data['keys']
        except Exception:
            raise JwtValidationError('Unable to obtain JWT signing keys') from None

    def signing_key(self, header, keys):
        algorithm = header.get('alg')
        if algorithm not in self.algorithms:
            raise JwtValidationError('JWT algorithm rejected')
        if 'crit' in header:
            raise JwtValidationError('Unsupported JWT critical header')
        kid = header.get('kid')
        if kid is not None and (not isinstance(kid, str) or not kid):
            raise JwtValidationError('Invalid JWT key identifier')
        candidates = []
        for key in keys:
            if (not isinstance(key, dict) or 'd' in key or 'k' in key
                    or key.get('use', 'sig') != 'sig'
                    or 'verify' not in key.get('key_ops', ['verify'])
                    or key.get('alg', algorithm) != algorithm
                    or (kid is not None and key.get('kid') != kid)):
                continue
            if algorithm in ('RS256', 'PS256') and key.get('kty') != 'RSA':
                continue
            if algorithm == 'ES256' and (key.get('kty') != 'EC' or key.get('crv') != 'P-256'):
                continue
            candidates.append(key)
        if len(candidates) != 1:
            raise JwtValidationError('Ambiguous or missing JWT signing key')
        key = jwt.PyJWK.from_dict(candidates[0], algorithm=algorithm).key
        if algorithm in ('RS256', 'PS256') and key.key_size < 2048:
            raise JwtValidationError('JWT signing key too small')
        return key

    def validate(self, encoded, *, keys=None, nonce=None, oidc=False):
        try:
            if not isinstance(encoded, str) or not encoded or len(encoded) > 65536:
                raise JwtValidationError('Invalid JWT')
            header = jwt.get_unverified_header(encoded)
            # Reject algorithms before fetching keys, never fetch token-supplied URLs.
            if header.get('alg') not in self.algorithms:
                raise JwtValidationError('JWT algorithm rejected')
            key = self.signing_key(header, self.public_keys() if keys is None else keys)
            claims = jwt.decode(encoded, key=key, algorithms=self.algorithms,
                                issuer=self.issuer, audience=self.audience, leeway=30,
                                options={'require': ['iss', 'aud', 'sub', 'exp', 'iat']})
            now = time.time()
            for name in ('iat', 'exp', 'nbf'):
                if name not in claims and name == 'nbf':
                    continue
                value = claims.get(name)
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise JwtValidationError('Invalid JWT time')
            if not isinstance(claims.get('sub'), str) or not claims['sub']:
                raise JwtValidationError('Invalid JWT subject')
            if oidc:
                if (not isinstance(nonce, str) or not nonce
                        or claims.get('nonce') != nonce):
                    raise JwtValidationError('Invalid OIDC nonce')
                audience = claims['aud']
                if (isinstance(audience, list) and len(audience) > 1
                        and claims.get('azp') != self.audience):
                    raise JwtValidationError('Invalid OIDC authorized party')
                if 'azp' in claims and claims['azp'] != self.audience:
                    raise JwtValidationError('Invalid OIDC authorized party')
            if oidc or self.max_age is not None:
                value = claims.get('auth_time')
                if (type(value) not in (int, float) or not math.isfinite(value)
                        or value > now + 30
                        or now - value > (self.max_age or 300) + 30):
                    raise JwtValidationError('Fresh authentication required')
            for name, expected in self.required_claims.items():
                if not claim_matches(claims, name, expected):
                    raise JwtValidationError('Required JWT assurance missing')
            return claims
        except Exception:
            raise JwtValidationError('JWT rejected') from None
