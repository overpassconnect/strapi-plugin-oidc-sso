'use strict';

/**
 * Send the browser back to the admin login with a short, safe error code that
 * the login-page button component renders as a human message. Returns a
 * *relative* path on purpose: same-origin redirects must not be built from a
 * (spoofable) Host header, which would be an open-redirect surface.
 */
function loginErrorUrl(code) {
  return `/admin/auth/login?sso_error=${encodeURIComponent(code)}`;
}

/**
 * Open-redirect guard. Only app-relative paths under /admin are honoured;
 * anything else (absolute URLs, protocol-relative //host, other paths) falls
 * back to the admin root.
 */
function safeReturnTo(returnTo) {
  if (typeof returnTo !== 'string') return '/admin';
  if (!returnTo.startsWith('/') || returnTo.startsWith('//')) return '/admin';
  if (returnTo !== '/admin' && !returnTo.startsWith('/admin/') && !returnTo.startsWith('/admin?')) {
    return '/admin';
  }
  return returnTo;
}

module.exports = { loginErrorUrl, safeReturnTo };
