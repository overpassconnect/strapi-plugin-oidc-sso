'use strict';

/**
 * Copy the `oidc-sso` block into your Strapi app's config/plugins.js.
 * Keep secrets in environment variables (.env), never in source control.
 *
 * Required env (issuer shown for Keycloak; use your provider's issuer URL):
 *   OIDC_ISSUER=https://kc.example.com/realms/mycompany
 *   OIDC_CLIENT_ID=strapi-admin
 *   OIDC_CLIENT_SECRET=xxxxxxxx
 *   STRAPI_PUBLIC_URL=https://cms.example.com
 */
module.exports = ({ env }) => ({
  'oidc-sso': {
    enabled: true,
    config: {
      // --- Provider -------------------------------------------------------
      issuer: env('OIDC_ISSUER'),
      clientId: env('OIDC_CLIENT_ID'),
      clientSecret: env('OIDC_CLIENT_SECRET'),
      scope: 'openid email profile',

      // --- URLs -----------------------------------------------------------
      // Register `${strapiPublicUrl}/oidc-sso/callback` as a valid redirect
      // URI in your provider's client/application settings.
      strapiPublicUrl: env('STRAPI_PUBLIC_URL'),

      // --- Token validation ----------------------------------------------
      usePKCE: true,
      clockToleranceSeconds: 30,
      idTokenSigningAlgs: ['RS256'],
      // 'client_secret_post' (Keycloak/Auth0) | 'client_secret_basic' (Okta default)
      tokenEndpointAuthMethod: 'client_secret_post',

      // --- Internal CA / TLS (only if the IdP uses a private CA) -----------
      // caCert: env('OIDC_CA_PEM'),
      // tlsRejectUnauthorized: true,

      // --- Role mapping ---------------------------------------------------
      // Left side = IdP role/group name, right side = Strapi admin role id OR code.
      // Find role ids under Settings -> Administration Panel -> Roles.
      // NOTE: mapping to Super Admin (usually role id 1) is REFUSED by default.
      // It only works if you also set allowSuperAdminMapping: true below, which
      // is file-only and off by default. Map to Editor/Author unless you truly
      // want SSO to be able to grant super admin. A mapping the plugin refuses
      // shows up in the logs as `no_mapped_role`.
      roleMapping: {
        'cms-editor': 'strapi-editor',
        'cms-author': 'strapi-author',
        // 'cms-superadmin': 1, // requires allowSuperAdminMapping: true (below)
      },
      // 'realm' | 'client' (Keycloak-shaped) | 'groups' (generic `groups` claim:
      // Okta/Auth0/Azure groups, or FreeIPA/LDAP via Keycloak federation)
      roleSources: ['realm'],
      // resourceRolesClient: env('OIDC_CLIENT_ID'),
      // groupsClaim: 'groups',
      // For FreeIPA groups: roleSources: ['groups'] and map path or leaf name,
      //   roleMapping: { '/cms-admins': 'strapi-editor', 'cms-authors': 'strapi-author' }.
      // IMPORTANT: the `groups` source only works if your provider actually puts a
      // groups claim in the token. In Keycloak add a "Group Membership" protocol
      // mapper (claim name = your groupsClaim, default `groups`) to the client or a
      // client scope; in Auth0/Okta add the groups claim/scope. Without it, the
      // groups source contributes nothing and you get `no_mapped_role`.

      // Convention instead of a mapping table: group `cms-<key>` grants the
      // Strapi role whose code/slugified name is <key> (super admin excluded).
      // dynamicRoleMatching: {
      //   enabled: true,
      //   groupPrefix: 'cms-',
      //   matchBy: ['code', 'name'],
      // },
      // File-only escape hatch: allow SSO to grant super admin (any source).
      // Keep false unless you really mean it. Cannot be changed from the UI.
      // allowSuperAdminMapping: false,

      // --- Provisioning ---------------------------------------------------
      provisioning: {
        autoCreate: true,
        defaultRoleId: null,
        requireVerifiedEmail: true,       // takeover guard - keep on
        matchExistingByEmail: true,
        allowEmailRelink: false,
        reactivateDisabledOnLogin: false, // deactivation stays a real revocation
        syncRolesOnLogin: true,
        updateProfileOnLogin: true,
      },
      protectLastSuperAdmin: true,

      // --- Session / logout ----------------------------------------------
      rememberMe: true,
      // Applies to GET /oidc-sso/logout only; Strapi's own top-bar logout ends
      // the Strapi session but leaves the IdP session alive.
      rpInitiatedLogout: true,
      // postLogoutRedirectUri: 'https://cms.example.com/admin/auth/login',

      // --- UI -------------------------------------------------------------
      buttonLabel: 'Sign in with SSO', // e.g. 'Log in with Keycloak'
      hideLocalLogin: false,

      // --- Login transaction signing -------------------------------------
      // Defaults to admin.auth.secret; set explicitly to rotate independently.
      // stateSecret: env('OIDC_STATE_SECRET'),
      stateTtlSeconds: 600,

      audit: true,
    },
  },
});
