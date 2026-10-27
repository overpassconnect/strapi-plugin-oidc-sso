'use strict';

const { SsoError, Codes } = require('../utils/errors');
const { cookieSecure } = require('../utils/cookies');
const { randomToken } = require('../utils/crypto');

const REFRESH_COOKIE_NAME = 'strapi_admin_refresh';

/**
 * Bridges a validated SSO login into a real Strapi admin session.
 *
 * Strapi >= 5.24 authenticates the admin panel with a SessionManager: a refresh
 * token in the HttpOnly `strapi_admin_refresh` cookie, exchanged by the SPA for
 * short-lived access tokens at POST /admin/access-token. We mint that refresh
 * token for the resolved user and set the cookie with options that mirror
 * Strapi's own `getRefreshCookieOptions`, so core reads it back identically.
 */
module.exports = ({ strapi }) => {
  function getManager() {
    if (typeof strapi.sessionManager !== 'function') {
      throw new SsoError(
        Codes.SESSION_FAILED,
        'strapi.sessionManager is unavailable; this plugin requires Strapi >= 5.24',
        { status: 500 }
      );
    }
    return strapi.sessionManager('admin');
  }

  // Mirrors packages/core/admin/.../shared/utils/session-auth.ts.
  function refreshCookieOptions(ctx, type, absoluteExpiresAtISO) {
    const get = (k, d) => strapi.config.get(k, d);
    const domain = get('admin.auth.cookie.domain', undefined) || get('admin.auth.domain', undefined);
    const path = get('admin.auth.cookie.path', '/admin');
    const sameSite = get('admin.auth.cookie.sameSite', undefined) ?? 'lax';

    const base = {
      httpOnly: true,
      secure: cookieSecure(strapi),
      overwrite: true,
      domain,
      path,
      sameSite,
      maxAge: undefined,
    };
    if (type === 'session') {
      return base;
    }
    const now = Date.now();
    const absolute = absoluteExpiresAtISO
      ? new Date(absoluteExpiresAtISO).getTime()
      : now + 7 * 24 * 3600 * 1000;
    const chosen = new Date(absolute);
    return { ...base, expires: chosen, maxAge: Math.max(0, chosen.getTime() - now) };
  }

  /**
   * Establish the admin session. Sets the HttpOnly refresh cookie AND mints the
   * first access token, returning both the sessionId and that access token. The
   * caller stashes the access token under a single-use completion id and bounces
   * the browser through the login page, which redeems the id and primes the SPA's
   * localStorage token. We mint here (rather than letting the SPA exchange the
   * refresh cookie on its own) so completion is bound to THIS login, not to
   * whatever refresh cookie happens to be in the browser (session-fixation
   * defense).
   */
  async function establishAdminSession(ctx, userId, { rememberMe = true } = {}) {
    const manager = getManager();
    const type = rememberMe ? 'refresh' : 'session';
    let result;
    try {
      result = await manager.generateRefreshToken(String(userId), undefined, { type });
    } catch (err) {
      throw new SsoError(Codes.SESSION_FAILED, `Could not create admin session: ${err.message}`, {
        status: 500,
      });
    }
    const { token, absoluteExpiresAt } = result;
    ctx.cookies.set(REFRESH_COOKIE_NAME, token, refreshCookieOptions(ctx, type, absoluteExpiresAt));
    // Mint the initial access token now so the browser completion step can be
    // bound to THIS login (via a server-held single-use id) instead of adopting
    // whatever refresh cookie happens to be present (session-fixation defense).
    let accessToken = null;
    try {
      const acc = await manager.generateAccessToken(token);
      if (acc && acc.token) accessToken = acc.token;
    } catch (err) {
      strapi.log.warn(`[oidc-sso] could not mint initial access token: ${err.message}`);
    }
    return { sessionId: result.sessionId, accessToken };
  }

  // Single-use, short-TTL, in-memory bindings of a completion id -> the access
  // token minted for that login. Per-instance (multi-instance needs sticky
  // sessions); entries are consumed on redemption and expire in 120s.
  const completions = new Map();
  function stashCompletion(accessToken) {
    const id = randomToken(24);
    const now = Date.now();
    for (const [k, v] of completions) {
      if (v.exp < now) completions.delete(k);
    }
    completions.set(id, { token: accessToken, exp: now + 120000 });
    return id;
  }
  function takeCompletion(id) {
    const rec = completions.get(id);
    if (!rec) return null;
    completions.delete(id); // single use
    if (rec.exp < Date.now()) return null;
    return rec.token;
  }

  function clearAdminSessionCookie(ctx) {
    const opts = refreshCookieOptions(ctx, 'session');
    ctx.cookies.set(REFRESH_COOKIE_NAME, '', { ...opts, maxAge: 0, expires: new Date(0) });
  }

  async function invalidateAllSessions(userId) {
    try {
      await getManager().invalidateRefreshToken(String(userId));
    } catch (err) {
      strapi.log.warn(`[oidc-sso] invalidateRefreshToken failed for user ${userId}: ${err.message}`);
    }
  }

  /**
   * Revoke the server-side session behind the current refresh cookie (so logout
   * actually ends the session, not just clears the browser cookie).
   *
   * SECURITY: the refresh cookie's JWT claims MUST NOT be trusted without
   * verification - a decode-only path let an unauthenticated attacker forge an
   * unsigned cookie `{userId: N}` and revoke any admin's sessions (DoS). We
   * therefore validate the token through the SessionManager (signature + active
   * session lookup) and revoke ONLY the specific verified session. A forged or
   * expired token yields isValid=false and revokes nothing.
   */
  async function invalidateByRefreshCookie(ctx) {
    const token = ctx.cookies.get(REFRESH_COOKIE_NAME);
    if (!token) return false;
    const manager = getManager();
    let result;
    try {
      result = await manager.validateRefreshToken(token);
    } catch (err) {
      return false;
    }
    if (!result || !result.isValid || !result.userId) return false;
    try {
      if (result.sessionId && typeof manager.revokeSessionById === 'function') {
        await manager.revokeSessionById(String(result.userId), String(result.sessionId));
      } else {
        await manager.invalidateRefreshToken(String(result.userId));
      }
      return true;
    } catch (err) {
      strapi.log.warn(`[oidc-sso] logout session revocation failed: ${err.message}`);
      return false;
    }
  }

  return {
    REFRESH_COOKIE_NAME,
    establishAdminSession,
    clearAdminSessionCookie,
    invalidateAllSessions,
    invalidateByRefreshCookie,
    stashCompletion,
    takeCompletion,
  };
};
