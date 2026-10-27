'use strict';

const { randomToken, createPkcePair, hmac, timingSafeEqual, base64url } = require('../utils/crypto');
const { getPluginConfig, ROUTE_BASE_PATH } = require('../utils/config');
const { cookieSecure } = require('../utils/cookies');
const { SsoError, Codes } = require('../utils/errors');

const TX_COOKIE = 'oidc_tx';

/**
 * Login-transaction store, implemented as a signed HttpOnly cookie on the Strapi
 * origin. It carries the CSRF `state`, the OIDC `nonce`, the PKCE `code_verifier`
 * and the post-login `returnTo`. Being cookie-backed it needs no server-side
 * storage and is safe across multiple Strapi instances / load balancers.
 *
 * The verifier deliberately never travels in the `state` query parameter (which
 * passes through the IdP and browser history); keeping it in an HttpOnly cookie
 * preserves PKCE's guarantee against authorization-code interception.
 */
module.exports = ({ strapi }) => {
  const secret = () => {
    const c = getPluginConfig(strapi);
    return c.stateSecret || strapi.config.get('admin.auth.secret') || strapi.config.get('server.app.keys')?.[0];
  };

  const cookieOptions = () => {
    const c = getPluginConfig(strapi);
    return {
      httpOnly: true,
      sameSite: 'lax', // sent on the top-level GET redirect back from the IdP
      secure: cookieSecure(strapi),
      overwrite: true,
      path: ROUTE_BASE_PATH,
      maxAge: (c.stateTtlSeconds || 600) * 1000,
    };
  };

  function sign(payloadObj) {
    const s = secret();
    if (!s) {
      throw new SsoError(
        Codes.STATE_INVALID,
        'No signing secret available (set plugin stateSecret or admin.auth.secret)',
        { status: 500 }
      );
    }
    const body = base64url(JSON.stringify(payloadObj));
    return `${body}.${hmac(s, body)}`;
  }

  function unsign(value) {
    const s = secret();
    if (!s || typeof value !== 'string' || !value.includes('.')) {
      throw new SsoError(Codes.STATE_INVALID, 'Malformed login transaction');
    }
    const [body, sig] = value.split('.');
    const expected = hmac(s, body);
    if (!timingSafeEqual(sig, expected)) {
      throw new SsoError(Codes.STATE_INVALID, 'Login transaction signature mismatch');
    }
    try {
      return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch (e) {
      throw new SsoError(Codes.STATE_INVALID, 'Login transaction payload unreadable');
    }
  }

  /** Begin a login: mint state/nonce/PKCE, persist them in the cookie. */
  function issue(ctx, { returnTo, rememberMe }) {
    const c = getPluginConfig(strapi);
    const state = randomToken(24);
    const nonce = randomToken(24);
    const pkce = c.usePKCE ? createPkcePair() : { verifier: null, challenge: null };
    const payload = {
      state,
      nonce,
      v: pkce.verifier,
      returnTo: returnTo || '/admin',
      rememberMe: rememberMe !== false,
      iat: Math.floor(nowSeconds()),
    };
    ctx.cookies.set(TX_COOKIE, sign(payload), cookieOptions());
    return { state, nonce, codeChallenge: pkce.challenge };
  }

  /** Complete a login: validate `state`, TTL, return the stored secrets, clear cookie. */
  function consume(ctx, stateParam) {
    const raw = ctx.cookies.get(TX_COOKIE);
    // Always clear, even on failure, so a stale transaction can't be replayed.
    ctx.cookies.set(TX_COOKIE, '', { ...cookieOptions(), maxAge: 0, expires: new Date(0) });

    if (!raw) {
      throw new SsoError(Codes.STATE_INVALID, 'No login transaction cookie (expired, blocked, or new tab)');
    }
    const payload = unsign(raw);

    const c = getPluginConfig(strapi);
    const ttl = c.stateTtlSeconds || 600;
    if (nowSeconds() - (payload.iat || 0) > ttl) {
      throw new SsoError(Codes.STATE_EXPIRED, 'Login transaction expired; please try again');
    }
    if (!stateParam || !timingSafeEqual(stateParam, payload.state)) {
      throw new SsoError(Codes.STATE_INVALID, 'State parameter does not match (possible CSRF)');
    }
    return { nonce: payload.nonce, codeVerifier: payload.v, returnTo: payload.returnTo, rememberMe: payload.rememberMe };
  }

  return { issue, consume };
};

function nowSeconds() {
  return Date.now() / 1000;
}
