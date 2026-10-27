'use strict';

const { getPluginConfig } = require('../utils/config');

/**
 * Structured audit logging for authentication events. Deliberately records only
 * non-secret identifiers (subject, email, userId, error code) - never tokens,
 * authorization codes, or full claim sets.
 */
module.exports = ({ strapi }) => {
  function record(event, data = {}) {
    const c = getPluginConfig(strapi);
    if (c.audit === false) return;

    const safe = {
      sub: data.sub,
      email: data.email,
      userId: data.userId,
      code: data.code,
      ip: data.ip,
    };
    Object.keys(safe).forEach((k) => safe[k] === undefined && delete safe[k]);
    strapi.log.info(`[oidc-sso][audit] ${event} ${JSON.stringify(safe)}`);
  }

  return { record };
};
