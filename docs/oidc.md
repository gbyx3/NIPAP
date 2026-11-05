# Optional browser OIDC login

OIDC is disabled by default. Local login and the existing login layout remain.
The adapter uses NIPAP's existing PyJWT dependency and its built-in key selection
and cache. It does not change the API `JwtAuth` configuration or authorization.
Authlib handles the browser authorization-code exchange; it brings joserfc
transitively, although NIPAP does not import or pin joserfc directly.

## Configuration

Install `nipap-www[oidc]` with the matching updated `pynipap`. Add
`oidc_config_file = /etc/nipap/oidc.json` to `[www]`. The file must be private
(no group/other permissions). Its state directory must be service-owned, mode
0700, on local storage shared by all web workers. Multi-host deployments and
interleaved asyncio requests are not supported.

Example using invented identities and no real credentials:

```json
{
  "transaction_db": "/var/lib/nipap/oidc/state.db",
  "providers": {
    "primary": {
      "label": "Organization sign-in",
      "issuer": "https://idp.example.test/",
      "authorization_endpoint": "https://idp.example.test/authorize",
      "token_endpoint": "https://idp.example.test/token",
      "jwks_uri": "https://idp.example.test/jwks",
      "redirect_uri": "https://ipam.example.test/auth/oidc/primary/callback",
      "client_id": "example-client",
      "client_secret": "REPLACE-LOCALLY",
      "algorithms": ["RS256"],
      "max_age": 300,
      "session_ttl": 900,
      "identities": {
        "immutable-subject": {
          "username": "reader",
          "full_name": "Example Reader",
          "readonly": true,
          "required_claims": {"authn": "certificate"}
        }
      }
    }
  }
}
```

The example assurance claim is not a standard AD FS claim. Configure the IdP to
require the intended certificate ceremony and verify the claims it actually
issues. Group membership or a generic MFA indication is not sufficient evidence.

Each provider has its own client, callback, issuer and identity map. Identity
keys are exact immutable subjects, never email addresses or display names.
`identity_claim` may name another reviewed immutable signed claim; `sub` remains
required for audit. The server owns username and read-only permissions.

Optional `scopes` must include `openid`; use it for provider-required resource
scopes. `ca_bundle` may specify a private CA file. Endpoints use verified HTTPS,
no redirects, finite timeouts and no environment proxy/netrc credentials.
Signing keys use PyJWT's five-minute cache. Token-supplied key URLs are ignored.
Allowed algorithms are RS256, PS256 and ES256.

## Security and compatibility

The flow uses state, nonce, PKCE S256 and `client_secret_basic`. ID tokens must
match the configured issuer, audience and algorithms, and contain numeric `iat`,
`exp` and a recent `auth_time`. Missing freshness or required assurance fails
closed. Login transactions are consumed once and expire after five minutes.

OIDC always enables the [browser protections](web-security.md): unsafe requests
need CSRF tokens; mutation GETs and GET logout are rejected. Custom callers need
POST and `X-XSRF-TOKEN`, or `_csrf` in HTML forms. The native form remains visible,
and `welcome_message` keeps its existing behavior.

No ID token, access token or PKCE verifier enters the Flask cookie. The existing
trusted web-to-backend account remains server-side; ID tokens are not forwarded
as API credentials. Backend authorization is still required. Audit access uses
the existing `audit_admins` allowlist and `<subject>@oidc:<provider>` identity.

All workers need the same Flask signing key. Identity removal and read-only
changes take effect on requests after configuration reload. Sessions have an
absolute expiry; local logout clears the cookie. Back-channel logout and central
session revocation are not implemented.

Do not log callback query strings: authorization codes can appear there. Keep
provider secrets, transaction databases and real deployment details out of Git.

## Checks before deployment

Test real certificate sign-in, native fallback, audit access, allowed and denied
writes, concurrent users, expiry, revoked mappings, callback replay and CSRF.
Verify TLS, private file permissions, log redaction and independent recovery.
Offline tests and package-install checks do not replace that acceptance.
