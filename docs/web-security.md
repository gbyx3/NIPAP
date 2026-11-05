# Optional browser security

Set `web_security_enabled = true` in `[www]` to enable browser protections without
an identity provider. This option defaults to false for legacy compatibility.
Safe post-login return paths and request-local authentication isolation apply
independently. Future external authentication integrations must enable these
protections before accepting external sessions.

Enabled mode requires HTTPS, secure cookies and CSRF tokens on unsafe requests.
Local login and logout forms carry `_csrf`; Angular and the legacy jQuery caller
send the same-origin `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`. Logout requires POST.
Legacy mutation endpoints reject GET; custom clients must use POST and include
the token. Read-only backend mutations are rejected before dispatch, in addition
to the backend's independent authorization. Session-only VRF filters remain usable.

No authentication protocol, provider, third-party dependency or IPAM data migration
is introduced here. Test local login/logout, reads, allowed writes and denied writes
with disposable data and your custom clients before enabling this compatibility
change. The offline tests do not replace browser/backend acceptance.
