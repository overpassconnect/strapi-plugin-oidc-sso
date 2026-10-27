'use strict';

const { getPluginConfig, buildCallbackUrl, ROUTE_BASE_PATH } = require('../utils/config');
const { pickEditable } = require('../utils/editable');

/**
 * Admin API behind RBAC (plugin::oidc-sso.settings.read / .update).
 * Never returns secrets: the locked block is a redacted view of file config.
 */
module.exports = ({ strapi }) => {
  const svc = (name) => strapi.plugin('oidc-sso').service(name);

  return {
    async getSettings(ctx) {
      const overrides = await svc('settings').load();
      const cfg = getPluginConfig(strapi);
      const adminRoles = await strapi.db
        .query('admin::role')
        .findMany({ select: ['id', 'name', 'code'] });

      ctx.body = {
        data: {
          // What is currently stored in the DB (may be {}).
          overrides,
          // The editable subset of the effective config (file merged with DB).
          effective: pickEditable(cfg),
          // Read-only context so operators can see how the plugin is wired.
          // Includes the security guards that are deliberately file-only.
          locked: {
            issuer: cfg.issuer,
            clientId: cfg.clientId,
            strapiPublicUrl: cfg.strapiPublicUrl,
            scope: cfg.scope,
            usePKCE: cfg.usePKCE !== false,
            tokenEndpointAuthMethod: cfg.tokenEndpointAuthMethod || 'client_secret_post',
            rpInitiatedLogout: cfg.rpInitiatedLogout !== false,
            redirectUri: cfg.strapiPublicUrl ? buildCallbackUrl(cfg.strapiPublicUrl) : `${ROUTE_BASE_PATH}/callback`,
            allowSuperAdminMapping: cfg.allowSuperAdminMapping === true,
            protectLastSuperAdmin: cfg.protectLastSuperAdmin !== false,
            requireVerifiedEmail: !cfg.provisioning || cfg.provisioning.requireVerifiedEmail !== false,
            matchExistingByEmail: !cfg.provisioning || cfg.provisioning.matchExistingByEmail !== false,
            allowEmailRelink: !!(cfg.provisioning && cfg.provisioning.allowEmailRelink),
            reactivateDisabledOnLogin: !!(cfg.provisioning && cfg.provisioning.reactivateDisabledOnLogin),
            audit: cfg.audit !== false,
          },
          adminRoles,
        },
      };
    },

    async updateSettings(ctx) {
      try {
        const saved = await svc('settings').update(ctx.request.body);
        svc('audit').record('settings_updated', {
          userId: ctx.state.user ? ctx.state.user.id : undefined,
          ip: ctx.request.ip,
        });
        ctx.body = { data: saved };
      } catch (err) {
        if (err.name === 'ValidationError') {
          ctx.status = 400;
          ctx.body = { error: { name: 'ValidationError', message: err.message } };
          return;
        }
        throw err;
      }
    },
  };
};
