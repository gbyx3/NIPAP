# OIDC implementation review notes

This is a review map for the optional browser integration, not a claim of completed
security review or deployment acceptance. See [configuration and operation](oidc.md).

## Changed boundaries

- `nipapwww/oidc.py`: explicit provider endpoints/issuers, confidential code clients,
  PKCE S256, fixed signature algorithms and claims, exact immutable identity maps,
  one-use browser/provider-bound SQLite transactions, absolute session expiry,
  CSRF/mutation checks and sanitized callback failures/success logging.
- Prerequisite browser security and auth-isolation changes: native fallback, safe return paths, thread-local
  authentication options and teardown. Review concurrent users/cached objects and
  trusted web-to-backend identity delegation, not just login handlers.
- Prerequisite web callers: mutation GETs migrate to POST; Angular and legacy jQuery carry
  same-origin CSRF tokens. Review compatibility for custom browser clients.
- Sign-in UI: existing application shell, styles and theme preference; local
  username/password always visible first, configured alternative methods below.
  Provider labels are administrator configuration, not token-derived privileges.
  No new external fonts/assets. Required sign-in
  notices use escaped `login_notice`; review migration from `welcome_message`.
- Optional dependencies and separate web-security CI allow local-only installations
  without importing OIDC libraries. Review source and distribution packaging.
- Shared `nipap.jwt_auth` verification hardens the existing API `JwtAuth` backend
  and replaces the web adapter's direct JWT-library use. Authlib still brings
  joserfc transitively. API tokens and ID tokens
  use distinct validation contexts; browser tokens are not forwarded to the API.

The OIDC module reuses `web_security.py`; it does not duplicate CSRF, secure-cookie,
mutation or read-only browser guards. External identity reload precedes shared
read-only enforcement. The Requests pin matches the existing backend requirement.
See [JWT migration and token boundaries](jwt-auth.md) for the required backend pins,
certificate assurance, request-scoped API credentials and remaining review gates.

## Review before packaging

Choose a base that retains the target release's existing fixes. In particular,
review XML-RPC connection cleanup as well as authentication-state isolation.
Applying a feature patch onto an installed release and rebuilding a branch
wholesale are different operations; passing feature tests does not prove all
release-specific fixes have been forward-ported.

Review negative cases for issuer/audience/authorized party/algorithm/key/provider
mix-up, nonce/state/PKCE mismatch and replay, missing assurance, identity revocation,
expiry, redirects, CSRF and concurrent read-only/administrator requests. Ensure
errors, proxies and access/APM logs never record codes, tokens or credentials.
Enforce backend read-only authorization independently of UI controls.

SQLite transactions support a single host with shared local state, not multi-host
web deployment. The synchronous client does not support interleaved asyncio tasks.
There is no provider back-channel logout or central session revocation. Evaluate
these limitations against the intended deployment rather than hiding them.

## Verification scope

CI installs `nipap`, `pynipap` and `nipap-www[oidc]` together with pip and runs
`pip check`, in addition to the isolated web tests. This exercises the actual
package resolver rather than bypassing declared backend dependencies. Native
PostgreSQL client build prerequisites are required for the existing psycopg2
dependency; no database service is needed for these checks.

Current offline tests exercise real signatures, mock-transport code exchange,
claims, one-use transactions, browser/server boundaries, native login, UI structure
and thread isolation. They do not replace real provider/hardware-key acceptance,
browser/backend integration, negative/revocation coverage or isolated restore.

Keep review examples synthetic, with reserved domains and invented identities.
Do not include production configuration, private endpoints, credentials, user
identities, operational records or live screenshots in public contributions.
