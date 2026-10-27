'use strict';

/**
 * register() runs before bootstrap, before the app is fully loaded.
 * We keep it side-effect free beyond a hard compatibility check so that a
 * missing SessionManager fails loudly and early rather than mid-login.
 */
module.exports = ({ strapi }) => {
  const cfg = strapi.config.get('plugin::oidc-sso') || strapi.config.get('plugin.oidc-sso');
  if (cfg && cfg.enabled === false) {
    return;
  }

  if (typeof strapi.sessionManager !== 'function') {
    strapi.log.error(
      '[oidc-sso] strapi.sessionManager is not available. This plugin requires ' +
        'Strapi >= 5.24 (session-based admin authentication). Admin SSO will not work.'
    );
  }
};
