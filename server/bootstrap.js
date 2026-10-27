'use strict';

const { getPluginConfig, buildCallbackUrl, ROUTE_BASE_PATH } = require('./utils/config');

/**
 * bootstrap() runs once the app is loaded. We:
 *   1. Surface the exact redirect_uri to register at the IdP (removes guesswork).
 *   2. Warm the OIDC discovery cache (best-effort; failure is non-fatal).
 */
module.exports = async ({ strapi }) => {
  const cfg = getPluginConfig(strapi);
  if (!cfg || cfg.enabled === false) {
    return;
  }

  const oidc = strapi.plugin('oidc-sso').service('oidc');

  // RBAC actions for the settings UI/API. Super admins hold these implicitly;
  // other roles are granted them under Settings → Roles → Plugins. NOTE:
  // settings.update is role-assignment power (whoever holds it controls the
  // role mapping) - grant it as carefully as user/role management itself.
  try {
    await strapi.service('admin::permission').actionProvider.registerMany([
      {
        section: 'plugins',
        displayName: 'Read SSO settings',
        uid: 'settings.read',
        pluginName: 'oidc-sso',
      },
      {
        section: 'plugins',
        displayName: 'Update SSO settings',
        uid: 'settings.update',
        pluginName: 'oidc-sso',
      },
    ]);
  } catch (err) {
    const detail = err && (err.details || err.message || err);
    strapi.log.warn(`[oidc-sso] could not register permission actions: ${JSON.stringify(detail)}`);
  }

  // Warm the DB-settings cache so synchronous config reads see overrides from
  // the first login onwards.
  try {
    await strapi.plugin('oidc-sso').service('settings').load();
  } catch (err) {
    strapi.log.warn(`[oidc-sso] settings cache warm failed: ${err.message}`);
  }

  // The redirect_uri is stable and must be registered verbatim in the provider's
  // client. When strapiPublicUrl is unset we can only show the path.
  if (cfg.strapiPublicUrl) {
    const redirectUri = buildCallbackUrl(cfg.strapiPublicUrl);
    strapi.log.info(`[oidc-sso] Register this redirect URI with your identity provider: ${redirectUri}`);
  } else {
    strapi.log.info(
      `[oidc-sso] Callback path is ${ROUTE_BASE_PATH}/callback . ` +
        `Set "strapiPublicUrl" in config to log the full redirect URI.`
    );
  }

  // Production safety checks - these are the two most common causes of silent
  // login failures or insecure sessions behind a reverse proxy.
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction) {
    if (!cfg.strapiPublicUrl) {
      strapi.log.warn(
        '[oidc-sso] Production without "strapiPublicUrl": redirect_uri is derived from ' +
          'request headers (spoofable Host). Set it explicitly.'
      );
    }
    if (strapi.config.get('admin.auth.cookie.secure') === false) {
      strapi.log.warn(
        '[oidc-sso] admin.auth.cookie.secure=false in production: the admin session cookie ' +
          'will not be marked Secure.'
      );
    }
    if (!strapi.config.get('server.proxy')) {
      strapi.log.warn(
        '[oidc-sso] server.proxy is not enabled: behind a TLS-terminating proxy, Strapi may ' +
          'not detect HTTPS, so Secure cookies will not be set and admin login will fail. ' +
          'Set proxy: { koa: true } in config/server.js.'
      );
    }
  }

  try {
    await oidc.getDiscovery();
    strapi.log.info(`[oidc-sso] OIDC discovery OK for issuer ${oidc.normalizedIssuer()}`);
  } catch (err) {
    strapi.log.warn(
      `[oidc-sso] Could not reach OIDC discovery at bootstrap ` +
        `(${err.message}). It will be retried on first login.`
    );
  }
};
