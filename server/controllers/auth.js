'use strict';

const {
  getPluginConfig,
  getPublicBaseUrl,
  buildCallbackUrl,
  stripTrailingSlash,
  ROUTE_BASE_PATH,
} = require('../utils/config');
const { loginErrorUrl, safeReturnTo } = require('../utils/redirect');
const { SsoError, Codes } = require('../utils/errors');
const { limited } = require('../utils/rate-limit');
const { cookieSecure } = require('../utils/cookies');

const IDH_COOKIE = 'oidc_idh';

module.exports = ({ strapi }) => {
  const svc = (name) => strapi.plugin('oidc-sso').service(name);

  /**
   * Persist the id_token so a later logout can be RP-initiated with id_token_hint.
   * Scoped to the logout path, Secure in production, and its lifetime tied to the
   * session (a session cookie when rememberMe is off) so an ephemeral login does
   * not leave a long-lived identity JWT behind.
   */
  function stashIdToken(ctx, cfg, idToken, rememberMe) {
    if (!cfg.rpInitiatedLogout || !idToken) return;
    const opts = {
      httpOnly: true,
      sameSite: 'lax',
      secure: cookieSecure(strapi),
      overwrite: true,
      path: `${ROUTE_BASE_PATH}/logout`,
    };
    if (rememberMe) {
      opts.maxAge = 7 * 24 * 3600 * 1000; // bounded, aligned with the refresh session
    }
    ctx.cookies.set(IDH_COOKIE, idToken, opts);
  }

  function clearIdToken(ctx, cfg) {
    ctx.cookies.set(IDH_COOKIE, '', {
      httpOnly: true,
      overwrite: true,
      path: `${ROUTE_BASE_PATH}/logout`,
      maxAge: 0,
      expires: new Date(0),
    });
  }

  function failToLogin(ctx, err) {
    const code = err instanceof SsoError ? err.code : Codes.PROVIDER_ERROR;
    // Full detail is server-side only; the browser receives just the short code.
    strapi.log.warn(`[oidc-sso] login failed (${code}): ${err.detail || err.message}`);
    return ctx.redirect(loginErrorUrl(code));
  }

  return {
    /** Public config for the login-page button (label, endpoints, flags). */
    async status(ctx) {
      const cfg = getPluginConfig(strapi);
      ctx.body = {
        enabled: cfg.enabled !== false,
        buttonLabel: cfg.buttonLabel,
        hideLocalLogin: cfg.hideLocalLogin === true,
        loginPath: `${ROUTE_BASE_PATH}/login`,
        logoutPath: `${ROUTE_BASE_PATH}/logout`,
      };
    },

    /**
     * Redeem a single-use completion id (issued by the callback) for the access
     * token minted for that login. The id is unguessable, single-use, and TTL'd;
     * an attacker cannot forge one, so a planted refresh cookie cannot be adopted.
     */
    async completeToken(ctx) {
      if (limited(ctx, `cmpl:${ctx.request.ip}`, 60, 60 * 1000)) return;
      const id = ctx.query.id;
      if (!id) {
        ctx.status = 400;
        ctx.body = { error: 'missing_id' };
        return;
      }
      const token = svc('session').takeCompletion(String(id));
      if (!token) {
        ctx.status = 404;
        ctx.body = { error: 'invalid_or_expired' };
        return;
      }
      ctx.body = { data: { token } };
    },

    /** Step 1: begin the Authorization Code + PKCE flow, redirect to the IdP. */
    async login(ctx) {
      const cfg = getPluginConfig(strapi);
      const baseUrl = getPublicBaseUrl(strapi, ctx, cfg);

      if (cfg.enabled === false) {
        return ctx.redirect(loginErrorUrl(Codes.DISABLED));
      }
      if (limited(ctx, `login:${ctx.request.ip}`, 30, 60 * 1000)) return undefined;

      // Production cookies are Secure and Koa refuses to set them on a plain-HTTP
      // request, so this instance is being reached without TLS or behind a proxy
      // Strapi does not trust. That is a server misconfiguration: say so in the
      // log, and do not let the login page blame the identity provider.
      if (cookieSecure(strapi) && !ctx.request.secure) {
        strapi.log.error(
          '[oidc-sso] Refusing to start SSO over plain HTTP while cookies must be Secure: serve Strapi over ' +
            'HTTPS, or behind a TLS-terminating proxy set proxy: { koa: true } in config/server.js.'
        );
        return ctx.redirect(loginErrorUrl(Codes.SESSION_FAILED));
      }

      const oidc = svc('oidc');
      const stateStore = svc('state-store');
      try {
        const redirectUri = buildCallbackUrl(baseUrl);
        const returnTo = safeReturnTo(ctx.query.returnTo);
        const { state, nonce, codeChallenge } = stateStore.issue(ctx, {
          returnTo,
          rememberMe: cfg.rememberMe,
        });
        const authUrl = await oidc.buildAuthorizationUrl({ redirectUri, state, nonce, codeChallenge });
        return ctx.redirect(authUrl);
      } catch (err) {
        return failToLogin(ctx, err);
      }
    },

    /** Step 2: the IdP redirects back with ?code&state. Validate, provision, log in. */
    async callback(ctx) {
      const cfg = getPluginConfig(strapi);
      const baseUrl = getPublicBaseUrl(strapi, ctx, cfg);
      const audit = svc('audit');

      if (limited(ctx, `cb:${ctx.request.ip}`, 30, 60 * 1000)) return undefined;

      // Provider-reported error (e.g. access_denied) arrives on the query string.
      if (ctx.query.error) {
        audit.record('provider_error', { code: ctx.query.error, ip: ctx.request.ip });
        return ctx.redirect(loginErrorUrl(Codes.PROVIDER_ERROR));
      }

      const oidc = svc('oidc');
      const stateStore = svc('state-store');
      const provisioning = svc('provisioning');
      const session = svc('session');

      try {
        const { code, state } = ctx.query;
        if (!code) {
          throw new SsoError(Codes.PROVIDER_ERROR, 'Authorization response is missing code');
        }
        // RFC 9207: if the provider returns the `iss` authorization-response
        // parameter, it MUST match our configured issuer (mix-up defense).
        if (ctx.query.iss && ctx.query.iss !== oidc.normalizedIssuer()) {
          throw new SsoError(Codes.PROVIDER_ERROR, 'Authorization response iss does not match the configured issuer');
        }
        // Validates state (CSRF) + TTL and returns the PKCE verifier + nonce.
        const tx = stateStore.consume(ctx, state);

        const redirectUri = buildCallbackUrl(baseUrl);
        const tokenSet = await oidc.exchangeCode({ code, redirectUri, codeVerifier: tx.codeVerifier });

        const idClaims = await oidc.validateIdToken(tokenSet.id_token, { nonce: tx.nonce });

        // Access tokens are JWTs on Keycloak/Auth0/Azure but may be OPAQUE on
        // other providers. Only require a verifiable access token when role
        // extraction actually reads from it ('realm'/'client' sources); with
        // 'groups' alone, the validated ID token is sufficient on its own.
        const sources = cfg.roleSources || ['realm'];
        const accessTokenRequired = sources.includes('realm') || sources.includes('client');
        let accessClaims = null;
        try {
          accessClaims = await oidc.validateAccessToken(tokenSet.access_token);
        } catch (err) {
          if (accessTokenRequired) throw err;
          strapi.log.info(
            '[oidc-sso] Access token is opaque or not client-bound; proceeding on the ID token alone'
          );
        }
        const idpRoles = oidc.extractRoles(accessClaims, idClaims);

        // Bind email and its verified flag to the SAME token. Never let the
        // access token's email_verified vouch for an email taken from the ID
        // token - an OR across tokens can only loosen the takeover gate.
        let email = '';
        let emailVerified = false;
        if (idClaims.email) {
          email = idClaims.email;
          emailVerified = idClaims.email_verified === true;
        } else if (accessClaims && accessClaims.email) {
          email = accessClaims.email;
          emailVerified = accessClaims.email_verified === true;
        }
        const { userId } = await provisioning.resolveUser({
          subject: idClaims.sub,
          issuer: oidc.normalizedIssuer(),
          sid: idClaims.sid || null, // OP session id, for back-channel sid logout
          email,
          emailVerified,
          firstname: idClaims.given_name || idClaims.name || '',
          lastname: idClaims.family_name || '',
          idpRoles,
        });

        const { accessToken } = await session.establishAdminSession(ctx, userId, { rememberMe: tx.rememberMe });
        stashIdToken(ctx, cfg, tokenSet.id_token, tx.rememberMe);

        audit.record('login_success', { sub: idClaims.sub, email, userId, ip: ctx.request.ip });
        // The admin SPA initializes its token from localStorage on cold load and
        // does NOT exchange the refresh cookie by itself. Bounce through the admin
        // login page with a single-use completion id that maps (server-side) to
        // THIS login's freshly-minted access token - the plugin's same-origin
        // (CSP-allowed) injector redeems it and primes the SPA. Binding to the id
        // (not to whatever refresh cookie is present) prevents session fixation.
        const target = safeReturnTo(tx.returnTo);
        if (!accessToken) {
          return ctx.redirect(loginErrorUrl(Codes.SESSION_FAILED));
        }
        const completionId = session.stashCompletion(accessToken);
        return ctx.redirect(`/admin/auth/login?oidc_complete=${completionId}&returnTo=${encodeURIComponent(target)}`);
      } catch (err) {
        const code = err instanceof SsoError ? err.code : Codes.PROVIDER_ERROR;
        audit.record('login_failure', { code, ip: ctx.request.ip });
        return failToLogin(ctx, err);
      }
    },

    /** RP-initiated logout: clear the Strapi session cookie and end the provider session. */
    async logout(ctx) {
      const cfg = getPluginConfig(strapi);
      if (limited(ctx, `logout:${ctx.request.ip}`, 30, 60 * 1000)) return undefined;
      const session = svc('session');
      const oidc = svc('oidc');

      // Revoke the SERVER-SIDE session, not just the browser cookie - otherwise a
      // previously captured refresh cookie keeps minting admin tokens after
      // "logout". Skip revocation for a cross-site navigation so a forced-logout
      // CSRF cannot tear down sessions (modern browsers send Sec-Fetch-Site).
      if (ctx.get('sec-fetch-site') !== 'cross-site') {
        await session.invalidateByRefreshCookie(ctx);
      }
      session.clearAdminSessionCookie(ctx);
      const idToken = ctx.cookies.get(IDH_COOKIE);
      clearIdToken(ctx, cfg);

      // post_logout_redirect_uri must be absolute for the IdP. Only send one when
      // we have a trusted, configured origin - never derive it from the request
      // Host. Without it the IdP falls back to its own configured post-logout page.
      const postLogout =
        cfg.postLogoutRedirectUri ||
        (cfg.strapiPublicUrl ? `${stripTrailingSlash(cfg.strapiPublicUrl)}/admin/auth/login` : null);
      if (cfg.rpInitiatedLogout) {
        try {
          const url = await oidc.endSessionUrl({ idTokenHint: idToken, postLogoutRedirectUri: postLogout });
          if (url) return ctx.redirect(url);
        } catch (err) {
          strapi.log.warn(`[oidc-sso] RP-initiated logout could not build end_session URL: ${err.message}`);
        }
      }
      return ctx.redirect('/admin/auth/login');
    },

    /** OIDC Back-Channel Logout: the IdP POSTs a logout_token when a session ends. */
    async backchannelLogout(ctx) {
      const oidc = svc('oidc');
      const session = svc('session');

      if (limited(ctx, `bcl:${ctx.request.ip}`, 30, 60 * 1000)) return;

      const logoutToken = ctx.request.body && ctx.request.body.logout_token;
      if (!logoutToken) {
        ctx.status = 400;
        ctx.body = { error: 'missing_logout_token' };
        return;
      }
      try {
        const { sub, sid } = await oidc.validateLogoutToken(logoutToken);
        const issuer = oidc.normalizedIssuer();
        const idq = strapi.db.query('plugin::oidc-sso.oidc-identity');
        // Resolve the account by sub (subject logout) or, failing that, by the
        // OP session id (sid logout). We revoke all of the resolved user's
        // Strapi sessions - the safe direction, since we cannot map an OP sid to
        // a single Strapi session id.
        let identity = null;
        if (sub) identity = await idq.findOne({ where: { subject: sub, issuer } });
        if (!identity && sid) identity = await idq.findOne({ where: { sid, issuer } });
        if (identity) {
          await session.invalidateAllSessions(identity.adminUserId);
          svc('audit').record('backchannel_logout', { sub, userId: identity.adminUserId });
        } else {
          strapi.log.info(`[oidc-sso] back-channel logout: no local identity for ${sub ? 'sub' : 'sid'}`);
        }
        ctx.status = 200;
        ctx.body = { ok: true };
      } catch (err) {
        strapi.log.warn(`[oidc-sso] back-channel logout rejected: ${err.message}`);
        ctx.status = 400;
        ctx.body = { error: 'invalid_logout_token' };
      }
    },
  };
};
