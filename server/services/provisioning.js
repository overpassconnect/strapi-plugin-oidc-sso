'use strict';

const { getPluginConfig } = require('../utils/config');
const { randomToken } = require('../utils/crypto');
const { SsoError, Codes } = require('../utils/errors');

const IDENTITY_UID = 'plugin::oidc-sso.oidc-identity';
const ADMIN_USER_UID = 'admin::user';
const ADMIN_ROLE_UID = 'admin::role';
const SUPER_ADMIN_CODE = 'strapi-super-admin';

/**
 * Resolves a validated OIDC identity to a Strapi admin user: linking a
 * pre-existing account, provisioning a new one (JIT), and keeping roles/profile
 * in sync - with guardrails against lockout, account takeover, and silent
 * re-activation of disabled admins.
 */
module.exports = ({ strapi }) => {
  const cfg = () => getPluginConfig(strapi);
  const log = strapi.log;

  const identityQuery = () => strapi.db.query(IDENTITY_UID);
  const userService = () => strapi.service(ADMIN_USER_UID);

  // The admin-role set (ids, codes, names) is read several times within a single
  // login (target resolution, super-admin chokepoint, last-super-admin guard).
  // Role DEFINITIONS effectively never change at runtime, so a short-lived memo
  // collapses those reads into one DB hit per login without meaningful staleness.
  // Per-user role ASSIGNMENTS are read separately (populate on the user), so this
  // cache never masks a permission change on an account.
  let rolesCache = null;
  async function loadRoles() {
    const now = Date.now();
    if (rolesCache && now - rolesCache.at < 5000) return rolesCache.roles;
    const roles = await strapi.db.query(ADMIN_ROLE_UID).findMany();
    rolesCache = { at: now, roles };
    return roles;
  }

  /** Normalize a role/group name for convention matching: 'Content Translators' -> 'content-translators'. */
  const slug = (s) =>
    String(s)
      .toLowerCase()
      .trim()
      .replace(/\s+/g, '-')
      .replace(/[^a-z0-9-]/g, '');

  const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

  async function resolveTargetRoleIds(idpRoles) {
    const c = cfg();
    const mapping = c.roleMapping || {};
    const roles = await loadRoles();
    const byId = new Map(roles.map((r) => [r.id, r]));
    const byCode = new Map(roles.map((r) => [r.code, r]));

    const targetIds = new Set();
    for (const idpRole of idpRoles) {
      if (!hasOwn(mapping, idpRole) || mapping[idpRole] == null) continue;
      const target = mapping[idpRole];
      let role = null;
      if (typeof target === 'number') role = byId.get(target);
      else role = byCode.get(target) || byId.get(Number(target));
      if (role) targetIds.add(role.id);
      else log.warn(`[oidc-sso] roleMapping target "${target}" (IdP role "${idpRole}") matches no Strapi role`);
    }

    // Convention-over-configuration: a group `${groupPrefix}<key>` grants the
    // Strapi role whose code or slugified name equals <key>, with no explicit
    // roleMapping entry. The prefix is the namespace guard.
    const dyn = c.dynamicRoleMatching || {};
    if (dyn.enabled === true) {
      // An empty prefix would match every group leaf; treat it as unset.
      const prefix = typeof dyn.groupPrefix === 'string' && dyn.groupPrefix.trim().length ? dyn.groupPrefix : 'cms-';
      const matchBy = Array.isArray(dyn.matchBy) ? dyn.matchBy : ['code', 'name'];
      const byNameSlug = new Map(roles.map((r) => [slug(r.name), r]));
      for (const idpRole of idpRoles) {
        const leaf = String(idpRole).split('/').filter(Boolean).pop() || '';
        if (!leaf.startsWith(prefix)) continue;
        const key = slug(leaf.slice(prefix.length));
        if (!key) continue;
        let role = null;
        if (matchBy.includes('code') && byCode.has(key)) role = byCode.get(key);
        if (!role && matchBy.includes('name') && byNameSlug.has(key)) role = byNameSlug.get(key);
        if (role) targetIds.add(role.id);
      }
    }
    return [...targetIds];
  }

  function applyRolePolicy(targetIds) {
    const c = cfg();
    if (targetIds.length > 0) return targetIds;
    if (c.provisioning.defaultRoleId != null) return [c.provisioning.defaultRoleId];
    // A Strapi admin user must hold at least one role; "no role" always denies.
    throw new SsoError(Codes.NO_ROLE, 'No identity-provider role/group maps to a Strapi admin role for this user');
  }

  /**
   * Single chokepoint for super-admin grants. NONE of the SSO role sources
   * (explicit roleMapping, dynamic matching, or defaultRoleId) may resolve to
   * super admin unless `allowSuperAdminMapping` is true - and that flag is
   * FILE/ENV-only, never runtime-editable. This means a holder of the
   * settings.update permission cannot escalate themselves (or anyone) to super
   * admin through the UI; only whoever controls config/plugins.js can authorise
   * it. Applied after applyRolePolicy so it also covers defaultRoleId.
   */
  async function enforceSuperAdminPolicy(targetIds) {
    if (cfg().allowSuperAdminMapping === true) return targetIds;
    const roles = await loadRoles();
    const superRole = roles.find((r) => r.code === SUPER_ADMIN_CODE);
    if (!superRole) return targetIds;
    const filtered = targetIds.filter((id) => id !== superRole.id);
    if (filtered.length !== targetIds.length) {
      log.warn(
        '[oidc-sso] Refused to grant super admin via SSO mapping ' +
          '(set allowSuperAdminMapping in file config to permit it).'
      );
    }
    if (filtered.length === 0) {
      throw new SsoError(Codes.NO_ROLE, 'Only super admin mapped, which SSO may not grant; login refused');
    }
    return filtered;
  }

  /**
   * Extends the super-admin chokepoint to the account-LINK path: SSO must not be
   * able to bind an IdP subject to a pre-existing super-admin admin user (an
   * email-match takeover) unless file-only allowSuperAdminMapping is set. Without
   * this, a holder of settings.update could set an IdP email to a super admin's
   * address and inherit that account via the email-match branch, bypassing the
   * role-grant chokepoint entirely.
   */
  async function assertSuperAdminLinkAllowed(user) {
    if (cfg().allowSuperAdminMapping === true) return;
    const isSuper = (user.roles || []).some((r) => r.code === SUPER_ADMIN_CODE);
    if (isSuper) {
      throw new SsoError(
        Codes.RELINK_REFUSED,
        'Refusing to link an SSO identity to a super-admin account (allowSuperAdminMapping is off)'
      );
    }
  }

  async function findAdminUser(id) {
    return strapi.db.query(ADMIN_USER_UID).findOne({ where: { id }, populate: ['roles'] });
  }

  async function findAdminUserByEmail(email) {
    if (!email) return null;
    const svc = userService();
    if (typeof svc.findOneByEmail === 'function') {
      const u = await svc.findOneByEmail(email);
      if (u) return findAdminUser(u.id);
      return null;
    }
    return strapi.db.query(ADMIN_USER_UID).findOne({ where: { email }, populate: ['roles'] });
  }

  /**
   * A verified email is required before any *email-keyed* decision (linking to an
   * existing admin, or provisioning a new admin whose primary key is the email).
   * Without this gate, an unverified/attacker-set IdP email could claim an
   * existing admin account. Subject (`sub`)-keyed re-login does not need it.
   */
  function emailKeyable(email, emailVerified) {
    const c = cfg();
    if (!email) return false;
    if (c.provisioning.requireVerifiedEmail !== false && emailVerified !== true) return false;
    return true;
  }

  /** Blocked is a hard ban; inactive denies unless explicitly allowed to re-activate. */
  function ensureLoginAllowed(user) {
    const c = cfg();
    if (!user) throw new SsoError(Codes.PROVISIONING_FAILED, 'Admin user could not be resolved');
    if (user.blocked === true) {
      throw new SsoError(Codes.USER_INACTIVE, 'This admin account is blocked in Strapi');
    }
    if (user.isActive === false && c.provisioning.reactivateDisabledOnLogin !== true) {
      throw new SsoError(Codes.USER_INACTIVE, 'This admin account is deactivated in Strapi');
    }
  }

  async function guardLastSuperAdmin(user, desiredRoleIds) {
    if (!cfg().protectLastSuperAdmin) return desiredRoleIds;
    const roles = await loadRoles();
    const superRole = roles.find((r) => r.code === SUPER_ADMIN_CODE);
    if (!superRole) return desiredRoleIds;

    const userHasSuper = (user.roles || []).some((r) => r.code === SUPER_ADMIN_CODE || r.id === superRole.id);
    const desiredHasSuper = desiredRoleIds.includes(superRole.id);
    if (userHasSuper && !desiredHasSuper) {
      let activeSupers = 2; // fail safe: only demote if we can prove they are not the last
      try {
        activeSupers = await strapi.db
          .query(ADMIN_USER_UID)
          .count({ where: { isActive: true, roles: { id: superRole.id } } });
      } catch (err) {
        log.warn(`[oidc-sso] Could not count super admins (${err.message}); keeping super-admin to be safe.`);
        return [...new Set([...desiredRoleIds, superRole.id])];
      }
      if (activeSupers <= 1) {
        log.warn(
          `[oidc-sso] Keeping super-admin on user ${user.id}: it is the last active super admin.`
        );
        return [...new Set([...desiredRoleIds, superRole.id])];
      }
    }
    return desiredRoleIds;
  }

  async function createUser({ email, firstname, lastname, roleIds }) {
    if (!cfg().provisioning.autoCreate) {
      throw new SsoError(
        Codes.PROVISIONING_FAILED,
        'User has no Strapi admin account and auto-provisioning is disabled'
      );
    }
    // SSO users authenticate at the IdP; a random, unknown password keeps the
    // record valid without granting a usable local credential.
    const password = `${randomToken(24)}Aa1!`;
    const created = await userService().create({
      email,
      firstname: firstname || email,
      lastname: lastname || '',
      roles: roleIds,
      password,
      isActive: true,
      registrationToken: null,
    });
    log.info(`[oidc-sso] Provisioned new admin user ${created.id} <${email}>`);
    return findAdminUser(created.id);
  }

  async function syncExistingUser(user, { email, firstname, lastname, roleIds }) {
    const c = cfg();
    const update = {};
    if (c.provisioning.updateProfileOnLogin) {
      if (email && email !== user.email) update.email = email;
      if (firstname && firstname !== user.firstname) update.firstname = firstname;
      if (lastname && lastname !== user.lastname) update.lastname = lastname;
    }
    if (c.provisioning.syncRolesOnLogin) {
      update.roles = await guardLastSuperAdmin(user, roleIds);
    }
    // Only re-activate a disabled account if explicitly permitted; the default is
    // to have denied such a login already in ensureLoginAllowed().
    if (user.isActive === false && c.provisioning.reactivateDisabledOnLogin === true) {
      update.isActive = true;
    }
    if (Object.keys(update).length > 0) {
      await userService().updateById(user.id, update);
    }
    return findAdminUser(user.id);
  }

  async function upsertIdentity(subject, issuer, email, adminUserId, sid) {
    const existing = await identityQuery().findOne({ where: { subject, issuer } });
    const data = { subject, issuer, email, adminUserId, lastLoginAt: new Date() };
    if (sid) data.sid = sid;
    if (existing) {
      await identityQuery().update({ where: { id: existing.id }, data });
      return;
    }
    try {
      await identityQuery().create({ data });
    } catch (err) {
      // Concurrent first-login race: the unique `subject` was created by a
      // parallel request between our findOne and create. Re-read and update.
      const raced = await identityQuery().findOne({ where: { subject } });
      if (raced) {
        await identityQuery().update({ where: { id: raced.id }, data });
      } else {
        throw err;
      }
    }
  }

  // Logins that could provision or link the same admin account run one at a
  // time within this process. Neither admin_users.email nor the identity's
  // subject is unique at the database level, so two concurrent first logins of
  // a new user (a double-clicked button with a live IdP session is enough) both
  // passed the "unknown subject" check and created two admin users. Keyed by the
  // normalized email so it also covers two IdP subjects claiming one email.
  // Separate instances can still race; multi-instance already needs sticky
  // sessions.
  const locks = new Map();
  async function withLock(key, fn) {
    const previous = locks.get(key) || Promise.resolve();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const tail = previous.then(() => gate);
    locks.set(key, tail);
    await previous;
    try {
      return await fn();
    } finally {
      release();
      if (locks.get(key) === tail) locks.delete(key);
    }
  }

  /**
   * @param {object} p
   * @param {string}   p.subject        stable OIDC `sub`
   * @param {string}   p.issuer
   * @param {string}   p.email
   * @param {boolean}  p.emailVerified  from the ID token's email_verified claim
   * @param {string}   p.firstname
   * @param {string}   p.lastname
   * @param {string[]} p.idpRoles  roles + groups already extracted
   * @returns {Promise<{ userId: number }>}
   */
  function resolveUser(p) {
    const normalizedEmail = p.email ? String(p.email).normalize('NFKC').toLowerCase() : '';
    const key = normalizedEmail ? `email:${normalizedEmail}` : `sub:${p.issuer}|${p.subject}`;
    return withLock(key, () => resolveUserNow(p));
  }

  async function resolveUserNow({ subject, issuer, sid, email, emailVerified, firstname, lastname, idpRoles }) {
    const c = cfg();
    // NFKC-normalize before lowercasing so visually-equal emails compare equal
    // and we link (not duplicate) an existing admin.
    const normalizedEmail = email ? String(email).normalize('NFKC').toLowerCase() : email;
    const keyable = emailKeyable(normalizedEmail, emailVerified);

    // Role/group policy is evaluated first: no access => no login, no provisioning.
    // Order: resolve mapped roles -> default-or-deny -> strip super admin unless
    // explicitly permitted in file config (covers every source uniformly).
    const targetRoleIds = await enforceSuperAdminPolicy(
      applyRolePolicy(await resolveTargetRoleIds(idpRoles))
    );

    // 1) Known subject -> its linked admin user (sub is the trust anchor).
    // Scoped by issuer: `sub` is only unique within an issuer.
    const identity = await identityQuery().findOne({ where: { subject, issuer } });
    if (identity) {
      const user = await findAdminUser(identity.adminUserId);
      if (user) {
        ensureLoginAllowed(user);
        const synced = await syncExistingUser(user, {
          email: keyable ? normalizedEmail : null, // never sync to an unverified email
          firstname,
          lastname,
          roleIds: targetRoleIds,
        });
        await upsertIdentity(subject, issuer, normalizedEmail, synced.id, sid);
        return { userId: synced.id };
      }
      log.warn(`[oidc-sso] Identity ${subject} pointed at missing user ${identity.adminUserId}; re-provisioning`);
      await identityQuery().delete({ where: { id: identity.id } });
    }

    // 2) Unknown subject, existing admin with this email - only with a VERIFIED email.
    if (c.provisioning.matchExistingByEmail && keyable) {
      const byEmail = await findAdminUserByEmail(normalizedEmail);
      if (byEmail) {
        // Never allow SSO to seize a super-admin account by email match.
        await assertSuperAdminLinkAllowed(byEmail);
        const otherIdentity = await identityQuery().findOne({ where: { adminUserId: byEmail.id } });
        if (otherIdentity && otherIdentity.subject !== subject && !c.provisioning.allowEmailRelink) {
          throw new SsoError(
            Codes.RELINK_REFUSED,
            `Email ${normalizedEmail} is already linked to a different identity-provider subject; relinking is disabled`
          );
        }
        ensureLoginAllowed(byEmail);
        const synced = await syncExistingUser(byEmail, {
          email: normalizedEmail,
          firstname,
          lastname,
          roleIds: targetRoleIds,
        });
        await upsertIdentity(subject, issuer, normalizedEmail, synced.id, sid);
        return { userId: synced.id };
      }
    }

    // 3) Brand-new user -> JIT provision. Requires a verified, usable email.
    if (!keyable) {
      if (!normalizedEmail) {
        throw new SsoError(Codes.NO_EMAIL, 'The identity provider did not provide an email claim for this user');
      }
      throw new SsoError(
        Codes.EMAIL_UNVERIFIED,
        'Identity-provider email is not verified; refusing to link or provision by an unverified email'
      );
    }
    const created = await createUser({ email: normalizedEmail, firstname, lastname, roleIds: targetRoleIds });
    ensureLoginAllowed(created);
    await upsertIdentity(subject, issuer, normalizedEmail, created.id, sid);
    return { userId: created.id };
  }

  return { resolveUser };
};
