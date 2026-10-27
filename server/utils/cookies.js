'use strict';

/**
 * Whether cookies should carry the Secure attribute.
 *
 * Defaults to Secure in production regardless of `ctx.request.secure` - the
 * admin panel must be served over HTTPS in production, and relying on
 * `ctx.request.secure` alone drops Secure when Strapi sits behind a
 * TLS-terminating proxy without `server.proxy` configured (a common
 * misconfiguration). An explicit `admin.auth.cookie.secure` boolean overrides.
 * Never Secure in development so http://localhost keeps working.
 */
function cookieSecure(strapi) {
  const configured = strapi.config.get('admin.auth.cookie.secure', undefined);
  if (typeof configured === 'boolean') return configured;
  return process.env.NODE_ENV === 'production';
}

module.exports = { cookieSecure };
