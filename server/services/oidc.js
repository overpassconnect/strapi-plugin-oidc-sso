'use strict';

const { importJWK, jwtVerify } = require('jose');
const { getJson, postForm } = require('../utils/http');
const { getPluginConfig, stripTrailingSlash } = require('../utils/config');
const { SsoError, Codes } = require('../utils/errors');

/**
 * Generic OIDC provider integration (Keycloak, Auth0, Okta, Azure AD, ...).
 *
 * Owns discovery caching, JWKS retrieval with rotation-aware refetch, the
 * authorization-code token exchange, and strict validation of ID and access
 * tokens. All HTTP goes through the TLS-aware helper so an internal CA works.
 */
module.exports = ({ strapi }) => {
  // Closure-scoped caches (the service is a singleton for the app lifetime).
  let discoveryCache = null; // { doc, fetchedAt }
  const jwksCache = new Map(); // jwks_uri -> { keys, fetchedAt }
  const seenJti = new Map(); // `${iss}:${jti}` -> expiry ms (back-channel replay guard)

  const cfg = () => getPluginConfig(strapi);

  /** Every provider endpoint must be https (except localhost for dev). */
  function assertHttps(urlStr, label) {
    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      throw new SsoError(Codes.DISCOVERY_FAILED, `${label} is not a valid URL`, { status: 502 });
    }
    const isLocal = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
    if (u.protocol !== 'https:' && !isLocal) {
      throw new SsoError(
        Codes.DISCOVERY_FAILED,
        `${label} must use https (got ${u.protocol}//${u.hostname}); refusing to use a cleartext provider endpoint`,
        { status: 502 }
      );
    }
    return urlStr;
  }

  const tlsOptions = () => {
    const c = cfg();
    return {
      timeoutMs: c.httpTimeoutMs,
      ca: c.caCert ? c.caCert : null,
      rejectUnauthorized: c.tlsRejectUnauthorized !== false,
    };
  };

  const normalizedIssuer = () => stripTrailingSlash(cfg().issuer);

  async function getDiscovery() {
    const c = cfg();
    const ttlMs = (c.discoveryTtlSeconds || 3600) * 1000;
    const now = Date.now();
    if (discoveryCache && now - discoveryCache.fetchedAt < ttlMs) {
      return discoveryCache.doc;
    }
    const url = assertHttps(
      `${normalizedIssuer()}/.well-known/openid-configuration`,
      'discovery URL'
    );
    let doc;
    try {
      doc = await getJson(url, tlsOptions());
    } catch (err) {
      throw new SsoError(Codes.DISCOVERY_FAILED, `Discovery fetch failed: ${err.message}`, {
        status: 502,
      });
    }
    // The discovery `issuer` must equal our configured issuer, else tokens we
    // later validate against this metadata would be trusted for the wrong realm.
    if (stripTrailingSlash(doc.issuer) !== normalizedIssuer()) {
      throw new SsoError(
        Codes.DISCOVERY_FAILED,
        `Discovery issuer mismatch: metadata says "${doc.issuer}" but config expects "${normalizedIssuer()}". ` +
          `This usually means the provider is behind a proxy advertising a different hostname ` +
          `(for Keycloak, set KC_HOSTNAME so realm URLs match the configured issuer).`,
        { status: 502 }
      );
    }
    // Refuse a discovery document that advertises cleartext endpoints even if the
    // issuer itself is https (a compromised/misconfigured OP could downgrade).
    assertHttps(doc.authorization_endpoint, 'authorization_endpoint');
    assertHttps(doc.token_endpoint, 'token_endpoint');
    assertHttps(doc.jwks_uri, 'jwks_uri');
    if (doc.end_session_endpoint) assertHttps(doc.end_session_endpoint, 'end_session_endpoint');

    discoveryCache = { doc, fetchedAt: now };
    return doc;
  }

  async function fetchJwks(jwksUri, { force = false } = {}) {
    const c = cfg();
    const cooldownMs = (c.jwksCooldownSeconds || 30) * 1000;
    const cached = jwksCache.get(jwksUri);
    const now = Date.now();
    if (!force && cached && now - cached.fetchedAt < cooldownMs) {
      return cached.keys;
    }
    // Throttle forced (kid-miss) refetches so a stream of tokens with bogus kids
    // cannot be used to hammer the JWKS endpoint (fetch amplification).
    if (force && cached && cached.lastForceAt && now - cached.lastForceAt < 5000) {
      return cached.keys;
    }
    let doc;
    try {
      doc = await getJson(jwksUri, tlsOptions());
    } catch (err) {
      // An outage of the key endpoint must not read as an invalid token.
      throw new SsoError(Codes.PROVIDER_UNREACHABLE, `JWKS fetch failed: ${err.message}`, { status: 502 });
    }
    const keys = Array.isArray(doc.keys) ? doc.keys : [];
    jwksCache.set(jwksUri, {
      keys,
      fetchedAt: now,
      lastForceAt: force ? now : cached && cached.lastForceAt,
    });
    return keys;
  }

  /**
   * jose key resolver bound to a specific JWKS uri. Selects the JWK by `kid`
   * (and `alg` when present). On a `kid` miss it refetches once, which is how
   * provider signing-key rotation is picked up without a restart.
   */
  function makeKeyResolver(jwksUri) {
    return async (protectedHeader) => {
      const { kid, alg } = protectedHeader;
      const pick = (keys) =>
        keys.find(
          (k) => (kid ? k.kid === kid : true) && (k.alg ? k.alg === alg : true) && (!k.use || k.use === 'sig')
        );

      let keys = await fetchJwks(jwksUri);
      let jwk = pick(keys);
      if (!jwk) {
        keys = await fetchJwks(jwksUri, { force: true });
        jwk = pick(keys);
      }
      if (!jwk) {
        // kid/alg are attacker-controlled JWT-header text; JSON-encode so a
        // crafted value with CR/LF cannot forge log lines.
        throw new SsoError(
          Codes.ID_TOKEN_INVALID,
          `No JWKS key matches kid=${JSON.stringify(String(kid))} alg=${JSON.stringify(String(alg))}`
        );
      }
      // Pin the algorithm to the key's own `alg` when the JWK declares one,
      // rather than trusting the attacker-supplied header alg.
      return importJWK(jwk, jwk.alg || alg);
    };
  }

  async function jwksUri() {
    const doc = await getDiscovery();
    if (!doc.jwks_uri) {
      throw new SsoError(Codes.DISCOVERY_FAILED, 'Discovery document has no jwks_uri');
    }
    return doc.jwks_uri;
  }

  async function buildAuthorizationUrl({ redirectUri, state, nonce, codeChallenge }) {
    const c = cfg();
    const doc = await getDiscovery();
    const url = new URL(doc.authorization_endpoint);
    // OIDC requires the openid scope; inject it if a custom scope omitted it.
    let scope = c.scope || 'openid email profile';
    if (!scope.split(/\s+/).includes('openid')) scope = `openid ${scope}`;
    const params = {
      response_type: 'code',
      client_id: c.clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      nonce,
    };
    if (c.usePKCE && codeChallenge) {
      params.code_challenge = codeChallenge;
      params.code_challenge_method = 'S256';
    }
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    return url.toString();
  }

  async function exchangeCode({ code, redirectUri, codeVerifier }) {
    const c = cfg();
    const doc = await getDiscovery();
    const form = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: c.clientId,
    };
    if (c.usePKCE && codeVerifier) {
      form.code_verifier = codeVerifier;
    }
    // Client authentication at the token endpoint. Keycloak/Auth0 accept the
    // secret in the body (client_secret_post); some providers (Okta default)
    // require HTTP Basic (client_secret_basic, RFC 6749 §2.3.1 encoding).
    const httpOptions = { ...tlsOptions() };
    if (c.tokenEndpointAuthMethod === 'client_secret_basic') {
      const basic = Buffer.from(
        `${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.clientSecret)}`
      ).toString('base64');
      httpOptions.headers = { authorization: `Basic ${basic}` };
    } else {
      form.client_secret = c.clientSecret;
    }
    let response;
    try {
      response = await postForm(doc.token_endpoint, form, httpOptions);
    } catch (err) {
      // Refused, timed out or reset: the provider is unreachable, which the
      // user must not be told is a cancelled or failed sign-in.
      throw new SsoError(Codes.PROVIDER_UNREACHABLE, `Token endpoint unreachable: ${err.message}`, {
        status: 502,
      });
    }
    const { status, json } = response;
    if (status !== 200 || !json) {
      const reason = (json && (json.error_description || json.error)) || `HTTP ${status}`;
      throw new SsoError(Codes.CODE_EXCHANGE_FAILED, `Token exchange failed: ${reason}`, {
        status: 502,
      });
    }
    // OIDC Core §3.1.3.3: token_type MUST be Bearer (case-insensitive) when present.
    if (json.token_type && String(json.token_type).toLowerCase() !== 'bearer') {
      throw new SsoError(Codes.CODE_EXCHANGE_FAILED, `Unexpected token_type "${json.token_type}"`, {
        status: 502,
      });
    }
    return json; // { access_token, id_token, refresh_token, token_type, expires_in, ... }
  }

  async function verify(token, { audience } = {}) {
    const c = cfg();
    const resolver = makeKeyResolver(await jwksUri());
    const options = {
      issuer: normalizedIssuer(),
      clockTolerance: c.clockToleranceSeconds || 30,
      algorithms: c.idTokenSigningAlgs || ['RS256'],
    };
    if (audience) options.audience = audience;
    // Guard against `alg: none` and header-declared key confusion: jose rejects
    // algorithms outside the allow-list above and never trusts embedded keys.
    const { payload } = await jwtVerify(token, resolver, options);
    return payload;
  }

  async function validateIdToken(idToken, { nonce }) {
    const c = cfg();
    let payload;
    try {
      payload = await verify(idToken, { audience: c.clientId });
    } catch (err) {
      if (err instanceof SsoError) throw err;
      throw new SsoError(Codes.ID_TOKEN_INVALID, `ID token invalid: ${err.code || err.message}`);
    }
    if (nonce) {
      if (!payload.nonce || payload.nonce !== nonce) {
        throw new SsoError(Codes.NONCE_MISMATCH, 'ID token nonce does not match the login request');
      }
    }
    // OIDC Core 3.1.3.7: multiple audiences MUST carry an azp; and whenever an
    // azp claim is present it MUST equal our client id (Keycloak emits azp even
    // for single-audience tokens). jose checks aud membership but not azp.
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp === undefined) {
      throw new SsoError(Codes.ID_TOKEN_INVALID, 'ID token has multiple audiences but no azp');
    }
    if (payload.azp !== undefined && payload.azp !== c.clientId) {
      throw new SsoError(Codes.ID_TOKEN_INVALID, 'ID token azp does not match this client');
    }
    return payload;
  }

  /**
   * Validate the access token WHEN it is a JWT from the same issuer (true for
   * Keycloak/Auth0/Azure). Keycloak places realm/client roles in the ACCESS
   * token, and its access-token `aud` is frequently "account" rather than our
   * client, so we validate signature/issuer/expiry strictly but assert client
   * binding via `azp`/`aud` instead of jose's audience check. Providers that
   * issue opaque access tokens fail here - the caller treats that as
   * non-fatal unless roles must be read from the access token.
   */
  async function validateAccessToken(accessToken) {
    const c = cfg();
    let payload;
    try {
      payload = await verify(accessToken); // no audience constraint here
    } catch (err) {
      if (err instanceof SsoError) throw err;
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, `Access token invalid: ${err.code || err.message}`);
    }
    const aud = payload.aud;
    const audOk =
      (Array.isArray(aud) ? aud.includes(c.clientId) : aud === c.clientId) || payload.azp === c.clientId;
    if (!audOk) {
      throw new SsoError(
        Codes.ACCESS_TOKEN_INVALID,
        'Access token is not bound to this client (azp/aud mismatch)'
      );
    }
    return payload;
  }

  /**
   * Collect the authorization strings the plugin will map to Strapi roles.
   * Sources:
   *   - 'realm'  -> access token `realm_access.roles` (Keycloak-shaped)
   *   - 'client' -> access token `resource_access[client].roles` (Keycloak-shaped)
   *   - 'groups' -> a configurable claim (default `groups`) read from the access
   *                 or ID token - the generic path for any provider (Okta groups,
   *                 Auth0 custom claims, Azure AD groups/roles, FreeIPA via
   *                 Keycloak federation, ...)
   * For groups we add both the full path (`/cms/editors`) and the leaf name
   * (`editors`) so roleMapping can key on whichever is convenient.
   */
  function extractRoles(accessPayload, idPayload) {
    const c = cfg();
    const sources = c.roleSources || ['realm'];
    const roles = new Set();
    if (sources.includes('realm')) {
      (accessPayload?.realm_access?.roles || []).forEach((r) => roles.add(r));
    }
    if (sources.includes('client')) {
      const client = c.resourceRolesClient || c.clientId;
      (accessPayload?.resource_access?.[client]?.roles || []).forEach((r) => roles.add(r));
    }
    if (sources.includes('groups')) {
      const claim = c.groupsClaim || 'groups';
      const groups =
        (accessPayload && accessPayload[claim]) || (idPayload && idPayload[claim]) || [];
      (Array.isArray(groups) ? groups : []).forEach((g) => {
        if (typeof g !== 'string') return;
        roles.add(g);
        const leaf = g.split('/').filter(Boolean).pop();
        if (leaf) roles.add(leaf);
      });
    }
    return [...roles];
  }

  /**
   * Validate an OIDC Back-Channel Logout token. Must be signed by the issuer,
   * bound to our client, and carry the backchannel-logout event. Returns
   * { sub, sid } for session revocation.
   */
  async function validateLogoutToken(logoutToken) {
    const c = cfg();
    let payload;
    try {
      payload = await verify(logoutToken, { audience: c.clientId });
    } catch (err) {
      if (err instanceof SsoError) throw err;
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, `Logout token invalid: ${err.code || err.message}`);
    }
    // events MUST be a JSON object containing the backchannel-logout member.
    const event = 'http://schemas.openid.net/event/backchannel-logout';
    const eventsIsObject =
      payload.events && typeof payload.events === 'object' && !Array.isArray(payload.events);
    if (!eventsIsObject || !Object.prototype.hasOwnProperty.call(payload.events, event)) {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token missing a valid backchannel-logout event');
    }
    // A logout token must not be usable as an ID token (no nonce allowed).
    if (payload.nonce) {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token must not contain a nonce');
    }
    if (!payload.sub && !payload.sid) {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token has neither sub nor sid');
    }
    // §2.4: iat and jti are REQUIRED. Enforce presence and use jti for replay
    // protection (reject a logout token whose jti+iss we have recently seen).
    if (typeof payload.iat !== 'number') {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token is missing iat');
    }
    if (!payload.jti) {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token is missing jti');
    }
    const now = Date.now();
    for (const [k, exp] of seenJti) {
      if (exp < now) seenJti.delete(k);
    }
    const jtiKey = `${normalizedIssuer()}:${payload.jti}`;
    if (seenJti.has(jtiKey)) {
      throw new SsoError(Codes.ACCESS_TOKEN_INVALID, 'Logout token replay detected (jti already seen)');
    }
    const expMs = payload.exp ? payload.exp * 1000 : now + 5 * 60 * 1000;
    seenJti.set(jtiKey, expMs);

    return { sub: payload.sub, sid: payload.sid };
  }

  async function endSessionUrl({ idTokenHint, postLogoutRedirectUri }) {
    const c = cfg();
    const doc = await getDiscovery();
    if (!doc.end_session_endpoint) return null;
    const url = new URL(doc.end_session_endpoint);
    if (idTokenHint) url.searchParams.set('id_token_hint', idTokenHint);
    if (postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
    url.searchParams.set('client_id', c.clientId);
    return url.toString();
  }

  return {
    normalizedIssuer,
    getDiscovery,
    buildAuthorizationUrl,
    exchangeCode,
    validateIdToken,
    validateAccessToken,
    validateLogoutToken,
    extractRoles,
    endSessionUrl,
  };
};
