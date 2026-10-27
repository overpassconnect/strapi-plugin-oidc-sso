'use strict';

const PLUGIN_ID = 'oidc-sso';

// Strapi mounts admin plugin routes at the plugin-name prefix; that mount point
// is not configurable, so this is a constant rather than a config knob (a
// configurable value could silently desync redirect_uri/cookie paths from the
// actual endpoints).
const ROUTE_BASE_PATH = `/${PLUGIN_ID}`;

/**
 * Read the effective plugin config: file/env config (defaults merged with the
 * host app override) with the DB-stored, admin-UI-editable overrides applied
 * on top. Only whitelisted keys can come from the DB (see utils/editable.js);
 * connection/crypto settings always come from the file.
 */
function getPluginConfig(strapi) {
  const fileCfg =
    strapi.config.get(`plugin::${PLUGIN_ID}`) ||
    strapi.config.get(`plugin.${PLUGIN_ID}`) ||
    {};
  let overrides = {};
  try {
    const svc = typeof strapi.plugin === 'function' && strapi.plugin(PLUGIN_ID)?.service?.('settings');
    if (svc && typeof svc.getCachedOverrides === 'function') {
      overrides = svc.getCachedOverrides() || {};
    }
  } catch (e) {
    overrides = {}; // registry not ready yet (early boot) - file config only
  }
  // Lazy require avoids a cycle: editable.js has no dependencies of its own.
  const { mergeEditable } = require('./editable');
  return mergeEditable(fileCfg, overrides);
}

/** Trim a trailing slash so string comparisons of URLs behave. */
function stripTrailingSlash(u) {
  return typeof u === 'string' ? u.replace(/\/+$/, '') : u;
}

/**
 * Derive the public base URL the browser used to reach Strapi.
 * Order of preference:
 *   1. Explicit `strapiPublicUrl` config (recommended in production).
 *   2. Reconstructed from proxy-aware request headers (requires server.proxy).
 */
function getPublicBaseUrl(strapi, ctx, cfg) {
  if (cfg.strapiPublicUrl) {
    return stripTrailingSlash(cfg.strapiPublicUrl);
  }
  // ctx.request.protocol / host already honour X-Forwarded-* when
  // `server.js` has `proxy: { koa: true }` (or proxy: true).
  const protocol = ctx.request.protocol || 'http';
  const host = ctx.request.host; // includes port if present
  return stripTrailingSlash(`${protocol}://${host}`);
}

/** The absolute, stable redirect_uri that must be registered at the IdP. */
function buildCallbackUrl(baseUrl) {
  return `${stripTrailingSlash(baseUrl)}${ROUTE_BASE_PATH}/callback`;
}

module.exports = {
  PLUGIN_ID,
  ROUTE_BASE_PATH,
  getPluginConfig,
  getPublicBaseUrl,
  buildCallbackUrl,
  stripTrailingSlash,
};
