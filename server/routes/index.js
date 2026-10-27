'use strict';

/**
 * These endpoints are mounted on the admin router at `/<plugin-name>/...`, i.e.
 * `/oidc-sso/login`, `/oidc-sso/callback`, etc. They are intentionally
 * public (`auth: false`) because they are reached before an admin session
 * exists (login start, provider callback, unauthenticated logout).
 *
 * Security does not rely on these being private: it relies on the signed state
 * cookie + PKCE + strict token validation performed inside the handlers.
 */
module.exports = {
  admin: {
    type: 'admin',
    routes: [
      {
        method: 'GET',
        path: '/status',
        handler: 'auth.status',
        config: { auth: false, policies: [] },
      },
      {
        method: 'GET',
        path: '/login',
        handler: 'auth.login',
        config: { auth: false, policies: [] },
      },
      {
        method: 'GET',
        path: '/callback',
        handler: 'auth.callback',
        config: { auth: false, policies: [] },
      },
      {
        method: 'GET',
        path: '/complete-token',
        handler: 'auth.completeToken',
        config: { auth: false, policies: [] },
      },
      {
        method: 'GET',
        path: '/logout',
        handler: 'auth.logout',
        config: { auth: false, policies: [] },
      },
      {
        method: 'POST',
        path: '/backchannel-logout',
        handler: 'auth.backchannelLogout',
        config: { auth: false, policies: [] },
      },
      // Settings API: authenticated admin only, gated by plugin RBAC actions
      // registered in bootstrap (grant under Settings → Roles → Plugins).
      {
        method: 'GET',
        path: '/settings',
        handler: 'settings.getSettings',
        config: {
          policies: [
            { name: 'admin::hasPermissions', config: { actions: ['plugin::oidc-sso.settings.read'] } },
          ],
        },
      },
      {
        method: 'PUT',
        path: '/settings',
        handler: 'settings.updateSettings',
        config: {
          policies: [
            { name: 'admin::hasPermissions', config: { actions: ['plugin::oidc-sso.settings.update'] } },
          ],
        },
      },
    ],
  },
};
