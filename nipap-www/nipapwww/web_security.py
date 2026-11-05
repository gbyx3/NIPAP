"""Opt-in browser protections shared by local and external authentication."""
import hmac
import secrets
from urllib.parse import urlsplit

from flask import abort, g, request, session


def local_return_path(value, default='/'):
    if (not isinstance(value, str) or not value.startswith('/')
            or value.startswith('//') or '\\' in value
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        return default
    parsed = urlsplit(value)
    return value if not parsed.netloc and not parsed.scheme else default


def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


def init_app(app):
    """Enable once, before serving requests. No identity-provider dependency."""
    if app.extensions.get('nipap_web_security'):
        return
    app.extensions['nipap_web_security'] = True
    app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Lax', SESSION_REFRESH_EACH_REQUEST=False)
    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def browser_boundary():
        g.web_security_enabled = True
        if request.endpoint == 'auth.logout' and request.method != 'POST':
            abort(405)
        mutating = request.endpoint and request.endpoint.startswith(tuple(
            'xhr.' + prefix for prefix in ('add_', 'edit_', 'remove_', 'del_')))
        if mutating and request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            abort(405)
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            expected = session.get('_csrf', '')
            supplied = request.headers.get('X-XSRF-TOKEN') or request.form.get('_csrf', '')
            if not expected or not hmac.compare_digest(expected.encode(), supplied.encode()):
                abort(403)
        backend_mutation = mutating and request.endpoint not in (
            'xhr.add_current_vrf', 'xhr.del_current_vrf')
        if backend_mutation and session.get('readonly') is True:
            abort(403)

    @app.after_request
    def browser_headers(response):
        response.set_cookie('XSRF-TOKEN', csrf_token(), secure=True,
                            httponly=False, samesite='Strict')
        response.headers['Referrer-Policy'] = 'no-referrer'
        if request.path.startswith('/auth/'):
            response.headers['Cache-Control'] = 'no-store'
        return response
