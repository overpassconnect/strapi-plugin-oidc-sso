'use strict';

const { validateSettings, isPlainSettingsObject } = require('../utils/editable');
const { PLUGIN_ID } = require('../utils/config');

const STORE_KEY = 'settings';

/**
 * DB-backed runtime settings, persisted in Strapi's core store (the same
 * mechanism native plugins use; rows live in strapi_core_store_settings).
 *
 * Reads are served from an in-memory cache so the hot login path stays
 * synchronous; the cache refreshes in the background when stale, so on a
 * multi-instance deployment another instance's change is picked up within
 * TTL_MS (or immediately on the instance that made it).
 */
module.exports = ({ strapi }) => {
  let cache = { overrides: {}, fetchedAt: 0 };
  const TTL_MS = 15000;

  const pluginStore = () => strapi.store({ type: 'plugin', name: PLUGIN_ID });

  async function load() {
    try {
      const value = await pluginStore().get({ key: STORE_KEY });
      cache = {
        overrides: value && typeof value === 'object' && !Array.isArray(value) ? value : {},
        fetchedAt: Date.now(),
      };
    } catch (err) {
      // Do NOT advance fetchedAt on failure: leaving it stale lets the next
      // read retry rather than serving old overrides for a further full TTL.
      strapi.log.warn(`[oidc-sso] could not load settings from store: ${err.message}`);
    }
    return cache.overrides;
  }

  /** Synchronous read for the hot path; refreshes in the background when stale. */
  function getCachedOverrides() {
    if (Date.now() - cache.fetchedAt > TTL_MS) {
      load().catch(() => {});
    }
    return cache.overrides;
  }

  /**
   * Replace the stored override object. The UI always sends the complete
   * editable set; an empty object clears all overrides (back to file config).
   */
  async function update(newSettings) {
    // Reject non-object bodies rather than silently coercing to {} (which would
    // wipe every override). An explicit empty object {} is still the reset path.
    if (!isPlainSettingsObject(newSettings)) {
      const err = new Error('Request body must be a JSON object of settings (send {} to reset to file config)');
      err.name = 'ValidationError';
      throw err;
    }
    const settings = newSettings;
    const errors = validateSettings(settings);
    if (errors.length > 0) {
      const err = new Error(errors.join('; '));
      err.name = 'ValidationError';
      throw err;
    }
    await pluginStore().set({ key: STORE_KEY, value: settings });
    cache = { overrides: settings, fetchedAt: Date.now() };
    return settings;
  }

  return { load, getCachedOverrides, update };
};
