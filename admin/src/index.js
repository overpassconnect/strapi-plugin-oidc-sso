'use strict';

import { injectSsoUi } from './inject';

/**
 * Admin-panel entry.
 *
 * 1. Registers a native settings section (Settings → OIDC SSO → Configuration)
 *    gated by the plugin's RBAC read permission; the page edits the DB-stored
 *    runtime policy (role mapping, dynamic matching, provisioning, UI).
 * 2. Attaches the login-page enhancer: Strapi has no official injection slot
 *    for the login screen, so a small DOM injector adds the SSO button and
 *    renders ?sso_error codes, re-applying across React re-renders. The local
 *    login form stays intact for break-glass access.
 */
export default {
  register(app) {
    if (app && typeof app.createSettingSection === 'function') {
      app.createSettingSection(
        {
          id: 'oidc-sso',
          intlLabel: { id: 'oidc-sso.settings.section', defaultMessage: 'OIDC SSO' },
        },
        [
          {
            intlLabel: { id: 'oidc-sso.settings.link', defaultMessage: 'Configuration' },
            id: 'oidc-sso-settings',
            to: 'oidc-sso',
            Component: () => import('./pages/SettingsPage'),
            permissions: [{ action: 'plugin::oidc-sso.settings.read', subject: null }],
          },
        ]
      );
    }
    if (app && typeof app.registerPlugin === 'function') {
      app.registerPlugin({
        id: 'oidc-sso',
        name: 'oidc-sso',
      });
    }
  },

  bootstrap() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;
    injectSsoUi();
  },
};
