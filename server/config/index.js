'use strict';

/**
 * Plugin configuration schema, defaults and validation.
 *
 * Every value can be overridden from `config/plugins.js` in the host Strapi app.
 * Secrets should come from environment variables, never be committed.
 */

const defaultConfig = {
  enabled: true,

  // --- OIDC provider -------------------------------------------------------
  // Issuer URL exactly as the provider reports it, e.g.
  //   Keycloak: https://kc.example.com/realms/mycompany
  //   Auth0:    https://tenant.eu.auth0.com/
  //   Okta:     https://tenant.okta.com/oauth2/default
  // This MUST equal the `iss` value the provider puts in its tokens.
  issuer: '',
  clientId: '',
  // Confidential client secret. Public clients are not supported for the admin
  // panel because the callback is handled server-side.
  clientSecret: '',
  scope: 'openid email profile',

  // Public base URL at which this Strapi is reachable by the browser, e.g.
  // https://cms.example.com . Used to build an exact, stable redirect_uri.
  // If empty, it is derived from the incoming request (honouring proxy headers),
  // which is convenient in dev but you should set it explicitly in production.
  strapiPublicUrl: '',

  // --- Token validation ----------------------------------------------------
  clockToleranceSeconds: 30,
  usePKCE: true,
  // Allowed signing algorithms for ID/access tokens (most providers use RS256).
  idTokenSigningAlgs: ['RS256'],
  // How the client secret is presented at the token endpoint:
  // 'client_secret_post' (Keycloak/Auth0 default) or 'client_secret_basic'
  // (required by some providers, e.g. Okta's default).
  tokenEndpointAuthMethod: 'client_secret_post',

  // --- HTTP / discovery ----------------------------------------------------
  discoveryTtlSeconds: 3600,
  jwksCooldownSeconds: 30,
  httpTimeoutMs: 8000,
  // TLS: only relax for an internal CA you control. Prefer supplying `caCert`.
  tlsRejectUnauthorized: true,
  caCert: '',

  // --- Provisioning & identity --------------------------------------------
  provisioning: {
    // Just-in-time create a Strapi admin user on first successful SSO login.
    autoCreate: true,
    // Strapi admin role id used when no IdP role/group maps. null => deny.
    defaultRoleId: null,
    // Require email_verified=true before any *email-keyed* link or provision.
    // This is the account-takeover guard: an unverified/attacker-set IdP email
    // must not be able to claim an existing admin account. Directory-backed
    // IdPs (e.g. FreeIPA via Keycloak) should map email_verified=true.
    requireVerifiedEmail: true,
    // On first SSO login, link an IdP identity to a pre-existing admin user
    // with the same (verified) email (e.g. your break-glass superadmin).
    matchExistingByEmail: true,
    // If a known email later presents a *different* IdP subject, relinking is
    // refused by default (protects against IdP email reassignment / takeover).
    allowEmailRelink: false,
    // Do NOT silently re-enable an admin you deactivated in Strapi. Deactivation
    // stays an effective revocation even for SSO users.
    reactivateDisabledOnLogin: false,
    // Keep the linked admin user's profile in sync with the IdP on each login.
    updateProfileOnLogin: true,
    // Re-evaluate and apply mapped roles on each login.
    syncRolesOnLogin: true,
  },

  // --- Role mapping --------------------------------------------------------
  // Map IdP role/group name -> Strapi admin role id OR role code.
  // Example: { 'cms-admin': 1, 'cms-editor': 'strapi-editor' }
  roleMapping: {},
  // Where to read authorization from. Any combination of:
  //   'realm'  -> access token realm_access.roles (Keycloak-shaped)
  //   'client' -> access token resource_access[client].roles (Keycloak-shaped)
  //   'groups' -> a configurable claim (generic: Okta/Auth0/Azure groups,
  //               FreeIPA/LDAP membership via Keycloak federation, ...)
  roleSources: ['realm'],
  // Client id to read resource roles from (defaults to `clientId`).
  resourceRolesClient: '',
  // Claim that carries group paths when roleSources includes 'groups'.
  groupsClaim: 'groups',

  // --- Dynamic role matching (convention over configuration) ---------------
  // When enabled, an IdP group named `${groupPrefix}<key>` grants the Strapi
  // admin role whose `code` or slugified name equals <key> - no roleMapping
  // entry needed (e.g. group "cms-translators" -> role named "Translators").
  // Results are unioned with explicit roleMapping. NOTE the trade-off: this
  // delegates role selection to whoever controls IdP group naming under the
  // prefix; explicit roleMapping is a stricter allow-list.
  dynamicRoleMatching: {
    enabled: false,
    groupPrefix: 'cms-',
    matchBy: ['code', 'name'],
  },

  // FILE/ENV-ONLY (never runtime-editable): whether ANY SSO mapping source
  // (roleMapping, dynamic matching, or defaultRoleId) may resolve to super
  // admin. Default false - SSO cannot grant platform-wide control, so a holder
  // of the runtime settings permission cannot escalate to super admin. Only
  // whoever controls config/plugins.js can turn this on.
  allowSuperAdminMapping: false,

  // Never let an SSO role sync remove the last remaining super admin.
  protectLastSuperAdmin: true,

  // --- Session -------------------------------------------------------------
  // Persistent refresh cookie (survives browser restart) vs session cookie.
  rememberMe: true,

  // --- Logout --------------------------------------------------------------
  // GET /oidc-sso/logout also ends the IdP session (RP-initiated logout).
  // Strapi's own top-bar logout does not go through this route: it ends only
  // the Strapi session and leaves the IdP session alive.
  rpInitiatedLogout: true,
  // Where the IdP returns the browser after logout. Defaults to the admin login.
  postLogoutRedirectUri: '',

  // --- UI ------------------------------------------------------------------
  buttonLabel: 'Sign in with SSO',
  // If true, the plugin advertises that local login should be hidden. The button
  // component honours this; the server never disables local login (break-glass).
  hideLocalLogin: false,

  // --- State signing -------------------------------------------------------
  // HMAC secret for the stateless, signed `state` (CSRF + PKCE binding).
  // Falls back to `admin.auth.secret` when empty.
  stateSecret: '',
  stateTtlSeconds: 600,

  // --- Auditing ------------------------------------------------------------
  audit: true,
};

// `strapi` is a runtime global that may not exist yet at config-validation
// time (and referencing an undeclared identifier throws). Reach it safely.
const warn = (msg) => {
  if (typeof global !== 'undefined' && global.strapi && global.strapi.log) {
    global.strapi.log.warn(msg);
  } else {
    // eslint-disable-next-line no-console
    console.warn(msg);
  }
};

/**
 * Validate configuration. Missing required values do NOT crash the app boot
 * (installing the plugin before configuring it should not take the whole CMS
 * down): they warn and leave the plugin inert until configured. Present-but-
 * malformed values still fail fast, because those are real mistakes.
 */
const validator = (config = {}) => {
  if (config.enabled === false) {
    return;
  }

  const required = ['issuer', 'clientId', 'clientSecret'];
  const missing = required.filter((k) => !config[k] || String(config[k]).trim() === '');
  if (missing.length > 0) {
    warn(
      `[oidc-sso] Not configured yet (missing: ${missing.join(', ')}). ` +
        `SSO endpoints will return errors until you set these in config/plugins.js ` +
        `(preferably from env). The rest of Strapi boots normally. See the plugin README.`
    );
    return; // nothing else to validate without an issuer
  }

  let issuer;
  try {
    issuer = new URL(config.issuer);
  } catch (e) {
    throw new Error(`[oidc-sso] "issuer" must be an absolute URL, got: ${config.issuer}`);
  }
  if (issuer.protocol !== 'https:' && issuer.hostname !== 'localhost' && issuer.hostname !== '127.0.0.1') {
    throw new Error(
      `[oidc-sso] "issuer" must use https (got ${issuer.protocol}//). ` +
        `Only localhost may use http.`
    );
  }
  if (config.issuer.endsWith('/')) {
    // Normalised later, but warn loudly: a trailing slash breaks exact `iss` match.
    warn('[oidc-sso] "issuer" has a trailing slash; it will be trimmed for the exact `iss` match.');
  }

  if (config.strapiPublicUrl) {
    try {
      // eslint-disable-next-line no-new
      new URL(config.strapiPublicUrl);
    } catch (e) {
      throw new Error(`[oidc-sso] "strapiPublicUrl" must be an absolute URL, got: ${config.strapiPublicUrl}`);
    }
  }

  if (config.tlsRejectUnauthorized === false && !config.caCert) {
    warn(
      '[oidc-sso] tlsRejectUnauthorized=false disables TLS verification for provider calls. ' +
        'Prefer supplying `caCert` with your internal CA instead.'
    );
  }
};

module.exports = {
  default: defaultConfig,
  validator,
};
