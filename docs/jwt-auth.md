# Shared JWT verification and certificate-backed AD FS login

`nipap.jwt_auth.JwtVerifier` is used by the existing API `JwtAuth` backend and
the optional browser OIDC adapter. It uses NIPAP's existing PyJWT library. The
browser extra uses Authlib for the authorization-code/PKCE exchange. Our direct
joserfc use and version pin are removed, but Authlib itself depends on joserfc,
so it is still installed transitively. JWT validation in NIPAP uses the shared
PyJWT verifier. No certificate, FIDO or AD FS deployment is configured automatically.

## API backend: explicit, fail-closed configuration

Install `nipap[jwt]` for asymmetric cryptographic support, then configure the
existing `[auth.backends.jwt]` backend. REST and XML-RPC use `Authorization: Bearer`
and the existing `jwt` backend; the password-backend suffix convention does not
obtain a token or initiate a browser redirect.

```ini
[auth.backends.jwt]
type = JwtAuth
jwk_url = https://issuer.example.test/jwks
issuer = https://issuer.example.test/
audience = https://api.example.test/
algorithms = RS256
group_claim_name = groups
ro_group = example-readers
rw_group = example-writers
```

**Upgrade compatibility:** issuer, audience and algorithm pins are now mandatory.
Old JWT configurations without these pins fail closed rather than accepting
tokens for another audience. Expiry, issued-at, subject, issuer and audience
claims are required. Existing Basic/password authentication remains available.
The original module-global JWK client is no longer shared between backends.

JWKS must use a fixed HTTPS URL with trusted TLS. Redirects, environment proxy/netrc
credentials and token-supplied key URLs are not used. Fetches have bounded time
and response size. Each verification currently fetches keys; provider-scoped key
caching/performance review is separate from this correctness-first implementation.

For certificate-only access, the administrator must configure AD FS to require
the intended certificate ceremony and issue reviewed signed assurance claims.
For example, if the issuer actually supplies these **synthetic example claims**:

```ini
required_claims = {"authn": "certificate"}
max_age = 300
identity_claim = directory_id
allowed_identities = ["example-immutable-directory-id"]
```

`max_age` requires a numeric, recent `auth_time`; omission is rejected. A generic
MFA indication or group membership alone is not proof of certificate use. Group
permissions still apply after identity/assurance validation, with read-only taking
precedence when both groups are present. Identity is populated only after verified
authentication. Client-supplied `auth_options` cannot override an untrusted JWT.

## Browser login is not API bearer forwarding

The [OIDC adapter](oidc.md) still handles redirects, code exchange, state, nonce,
PKCE and session creation. It calls the same verifier with an ID-token profile,
requiring nonce, fresh authentication and the browser client's audience. Exact
immutable identity maps remain server-controlled.

An **ID token authenticates the browser session**; an **access token is for its
API audience**. Configure distinct intended audiences and any issuer-specific
token-purpose claims. A JWT signature alone cannot distinguish token purpose.
Never forward an ID token as an API access credential. This integration retains
the existing trusted web-to-backend delegation: neither ID nor access tokens are
stored in the Flask cookie, and the callback does not set `pynipap.bearer_token`.

## Optional request-scoped API access tokens

For synchronous clients that already possess an appropriate API access token:

```python
try:
    pynipap.AuthOptions({"authoritative_source": "example-client"})
    pynipap.AuthOptions.set_bearer_token(access_token)
    # Make the intended API calls here. Never log or persist access_token.
finally:
    pynipap.AuthOptions.clear()
```

The override is thread-local and shared object-cache reads/writes are disabled
for that request. Setting `None` explicitly suppresses the legacy global token;
clearing restores legacy single-identity behavior. Do not share live transports
between users; bearer requests require HTTPS and a URI without embedded Basic credentials.
Do not use this synchronous client for interleaved asyncio tasks.
Tokens must be supplied from approved protected memory/storage, never browser
cookies, command arguments, logs or repository files. The browser adapter does
not obtain, retain or forward an API token in this change.

## Review and acceptance

Tests cover real signatures/claims, certificate-assurance rejection, Basic/Bearer
dispatch through both real API decorators, identity/role restrictions, ID-token
nonce/audience boundaries, concurrent request tokens, and shared-cache isolation.
Actual combined package installation is also checked. These are offline tests,
not live AD FS/hardware-key acceptance, a penetration test or deployment approval.
The inherited `flask-xml-rpc-re` package imports `pkg_resources`; the test runtime
explicitly supplies Setuptools 80.9.0 for that legacy requirement. Modernizing
that existing XML-RPC dependency is separate work, not silently bypassed here.
