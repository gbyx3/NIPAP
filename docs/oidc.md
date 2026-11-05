# Optional browser OIDC login

Development feature: offline unit coverage is not deployment acceptance. Test
with the selected identity providers, browser UI and backend before deployment.
Existing local authentication remains available and OIDC is disabled by default.
This does not enable or depend on the backend JWT authentication plugin.

## Installation and configuration

Install `nipap-www[oidc]` with the matching updated `pynipap`. The latter isolates
authentication options between synchronous worker threads. This client is not
intended for interleaved asyncio tasks. All web workers must use the same Flask
signing key and a private local transaction database directory. Multi-host web
deployments are not supported by this SQLite transaction store.

Add `oidc_config_file = /etc/nipap/oidc.json` to `[www]` in the existing config.
The JSON file must be a regular file with no group/other permissions, readable
by the web service. Create the state directory owned by that service, mode 0700.
The database and its short-lived PKCE secrets are private runtime state, not
publication or troubleshooting artifacts.

Example (reserved domains, synthetic identities, no real credentials):

```json
{
  "transaction_db": "/var/lib/nipap/oidc/state.db",
  "providers": {
    "primary": {
      "label": "Primary identity provider",
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
        "provider-issued-immutable-subject": {
          "username": "reader",
          "full_name": "Example Reader",
          "readonly": true,
          "required_claims": {
            "acr": "provider-specific-reviewed-assurance"
          }
        }
      }
    }
  }
}
```

Add further named providers using separate clients, callback URIs, signing keys,
issuers and subject mappings. Do not copy assurance strings between providers:
configure the provider to enforce the required authentication ceremony and review
its actual claims. Map only approved immutable subjects; usernames, email,
display names and token-supplied roles do not authorize users. Additional required
claims are exact JSON-value matches. Use a distinct username for each mapped
identity where audit attribution must distinguish them.

Providers with pairwise subjects may instead set `identity_claim` to an explicitly
reviewed, issuer-signed immutable directory identifier. The `identities` keys then
match that claim; the standard `sub` remains required and is retained for audit.
Never select an email address or mutable login name as the identity claim.
Optional `scopes` is a list containing `openid` and any provider-required resource
scopes; scope values cannot be supplied by browser requests.

The client requests `openid`, PKCE S256, nonce, and fresh authentication using
`max_age`. ID tokens must contain numeric `iat`, `exp` and `auth_time`; providers
that omit `auth_time` are rejected, not silently downgraded. Issuer and endpoint
URLs are explicit administrator-reviewed HTTPS settings; dynamic discovery and
HTTP redirects are not followed. Use optional `ca_bundle` for a trusted private
CA bundle; disabling certificate verification is prohibited. Environment proxy
and netrc credentials are deliberately ignored for OIDC outbound requests.

Only RS256, PS256 and ES256 may be configured. Confidential clients use
`client_secret_basic`. Keys are fetched from that provider's fixed JWKS URL.
No access, refresh or ID token or PKCE verifier is put in the browser session.
The signed Flask cookie carries mapped identity and absolute session expiry;
protect and rotate its signing key using the existing operational procedure.
Identity allowlist removal and read-only changes take effect on the next request
after configuration reload. There is no provider back-channel logout or central
session-revocation service; local logout clears the current browser cookie.

## Authorization and browser compatibility

The sign-in page retains the existing application shell, styles and color theme.
The native username/password form is always visible, with alternative provider
choices below it as independent CSRF-protected forms. Layout alternatives are
reviewed separately from this authentication integration.
Optional `[www] login_notice` supplies escaped sign-in notices (including any
required access/legal notice). The existing `welcome_message` remains an
application message and is no longer displayed on the sign-in page. Review that
setting when upgrading if it previously carried a mandatory sign-in notice.

The existing trusted web-to-backend account remains server-side. Do not expose
its credentials or XML-RPC service to browsers. Read-only enforcement remains
required in the backend; web mutation rejection is an additional safeguard.
Audit access uses the explicit existing `audit_admins` allowlist and the identity
format `<immutable-subject>@oidc:<provider-name>`, not the friendly username.
Do not grant Audit access merely because a token says `readonly=false`.

When OIDC is enabled, unsafe requests require a CSRF token. Native login and OIDC
buttons include it; Angular and the legacy jQuery UI echo the same-origin
`XSRF-TOKEN` cookie in `X-XSRF-TOKEN`. Mutating legacy GET endpoints are rejected.
Consumers must use POST and include that header; HTML form consumers can send
`_csrf`. Return paths must be local. Callback responses use no-store and
no-referrer. Disable/redact callback query strings in frontend, reverse-proxy,
APM and web-server access logs: authorization codes must not enter logs.

## Acceptance before deployment

- Test each provider using its real assurance ceremony, without adding production
  names, addresses, claims or credentials to this repository.
- Verify local fallback independently, including login/logout and Audit access.
- Exercise both Angular and legacy UI reads and authorized writes in disposable
  test data; verify backend read-only denial independently.
- Test parallel read-only/administrator sessions, expired sessions, revoked
  identity mappings, wrong provider/subject/audience, callback replay and CSRF.
- Verify trusted TLS and bounded outbound network permissions, restart behavior,
  private runtime-file permissions and logs free of codes/tokens.
- Retain independent recovery and a scoped rollback; do not infer recovery from
  unit-test success.

Local tests:

```sh
PYTHONPATH=nipap-www:nipap:pynipap python -B -m unittest discover -s tests -p 'test_web_*.py'
python -B -m unittest discover -s tests -p test_auth_options_isolation.py
```
