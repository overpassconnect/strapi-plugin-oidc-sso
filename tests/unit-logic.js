'use strict';
/* Smoke test: load the whole plugin server graph against a mocked strapi and
   exercise the load-bearing logic, including the security fixes. */

const path = require('path');
const DIR = path.resolve(__dirname, "..");
const R = (p) => require(path.join(DIR, p));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('PASS', name); }
  else { fail++; console.log('FAIL', name, extra !== undefined ? JSON.stringify(extra) : ''); }
}

const defaults = R('server/config').default;
const pluginCfg = {
  ...defaults,
  issuer: 'https://kc.example.com/realms/acme',
  clientId: 'strapi-admin',
  clientSecret: 'secret',
  roleMapping: { 'cms-editor': 'strapi-editor', 'cms-boss': 1, 'editors': 'strapi-editor' },
  roleSources: ['realm'],
};

const flatConfig = { 'admin.auth.secret': 'unit-test-secret', 'admin.auth.cookie.path': '/admin' };

// Mutable mock state so tests can vary identity/user status.
let created = null;
let revoked = [];
let mockIdentityBySubject = null;
let mockUserActive = true;
let mockUserBlocked = false;
let mockUserByEmail = null;
let mockUserRoles = [{ id: 4, code: 'strapi-editor' }];

const strapi = {
  log: { info() {}, warn() {}, error() {} },
  config: { get(key, def) { if (key === 'plugin::oidc-sso') return pluginCfg; if (key in flatConfig) return flatConfig[key]; return def; } },
  sessionManager(origin) {
    return {
      async generateRefreshToken(userId, deviceId, opts) {
        return { token: `refresh-for-${userId}-${opts.type}`, sessionId: 'sid-1', absoluteExpiresAt: new Date(Date.now() + 3600 * 1000).toISOString() };
      },
      async generateAccessToken(refreshToken) { return { token: `access-for-${refreshToken}` }; },
      async validateRefreshToken(token) { return token === 'valid-refresh' ? { isValid: true, userId: '42', sessionId: 'sid-1' } : { isValid: false, error: 'invalid_token' }; },
      async revokeSessionById(userId, sessionId) { revoked.push({ userId, sessionId }); return true; },
      async invalidateRefreshToken(userId) { revoked.push({ userId, all: true }); },
    };
  },
  service(uid) {
    if (uid === 'admin::user') {
      return {
        async findOneByEmail() { return mockUserByEmail; },
        async create(attrs) { created = attrs; return { id: 99 }; },
        async updateById(id) { return { id }; },
      };
    }
    return {};
  },
  db: {
    query(uid) {
      if (uid === 'admin::role') return { async findMany() { return [{ id: 1, code: 'strapi-super-admin', name: 'Super Admin' }, { id: 4, code: 'strapi-editor', name: 'Editor' }, { id: 7, code: 'translators', name: 'Translators' }]; } };
      if (uid === 'admin::user') {
        return {
          async findOne({ where }) { return { id: where.id || 99, isActive: mockUserActive, blocked: mockUserBlocked, email: 'boss@acme.com', firstname: 'B', lastname: 'Oss', roles: mockUserRoles }; },
          async count() { return 2; },
        };
      }
      if (uid === 'plugin::oidc-sso.oidc-identity') {
        return {
          async findOne({ where }) { if (where.subject) return mockIdentityBySubject; return null; },
          async create() { return {}; }, async update() { return {}; }, async delete() { return {}; },
        };
      }
      return { async findOne() { return null; } };
    },
  },
  store({ type, name }) {
    return {
      get: async () => mockStore,
      set: async ({ value }) => { mockStore = value; },
    };
  },
  plugin() {
    return { service: (n) => (svcCache[n] = svcCache[n] || R('server/services')[n]({ strapi })) };
  },
};
let mockStore = null;
const svcCache = {};

const server = R('server');
check('server exports register/bootstrap/config/services', !!(server.register && server.bootstrap && server.config && server.services));
check('routes expose 8 admin endpoints', server.routes.admin.routes.length === 8);
const authRoutes = server.routes.admin.routes.filter(r => r.path !== '/settings');
const settingsRoutes = server.routes.admin.routes.filter(r => r.path === '/settings');
check('6 auth routes are public (auth:false)', authRoutes.length === 6 && authRoutes.every(r => r.config.auth === false));
check('settings routes are authenticated + RBAC-gated', settingsRoutes.length === 2 && settingsRoutes.every(r =>
  r.config.auth !== false &&
  r.config.policies.some(p => p.name === 'admin::hasPermissions' && p.config.actions[0].startsWith('plugin::oidc-sso.settings.'))));

// config validator
// Missing required config must NOT throw (installing before configuring must
// not take the whole app down); it warns and leaves the plugin inert.
try { server.config.validator({ enabled: true, clientId: 'x', clientSecret: 'y' }); check('validator tolerates missing issuer (boot-safe)', true); }
catch (e) { check('validator tolerates missing issuer (boot-safe)', false, e.message); }
try { server.config.validator({ enabled: true, issuer: 'http://evil/realms/a', clientId: 'x', clientSecret: 'y' }); check('validator rejects http issuer', false); }
catch (e) { check('validator rejects http issuer', /https/i.test(e.message)); }

// crypto / PKCE
const crypto = R('server/utils/crypto');
const pkce = crypto.createPkcePair();
check('PKCE verifier in RFC bounds', pkce.verifier.length >= 43 && pkce.verifier.length <= 128);
check('PKCE challenge base64url', /^[A-Za-z0-9_-]+$/.test(pkce.challenge));

// redirect guards - now RELATIVE (Host-header fix)
const { safeReturnTo, loginErrorUrl } = R('server/utils/redirect');
check('safeReturnTo allows /admin/x', safeReturnTo('/admin/content') === '/admin/content');
check('safeReturnTo blocks external', safeReturnTo('https://evil.com') === '/admin');
check('safeReturnTo blocks //host', safeReturnTo('//evil.com') === '/admin');
check('loginErrorUrl is relative (no host)', loginErrorUrl('no_mapped_role') === '/admin/auth/login?sso_error=no_mapped_role');

// state-store round-trip + tamper
const stateStore = R('server/services/state-store')({ strapi });
const jar = {};
const mkCtx = (query = {}) => ({ request: { secure: false, ip: '127.0.0.1', protocol: 'https', host: 'cms.example.com' }, query, cookies: { set: (k, v) => { jar[k] = v; }, get: (k) => jar[k] } });
const issued = stateStore.issue(mkCtx(), { returnTo: '/admin/content', rememberMe: true });
const consumed = stateStore.consume(mkCtx({ state: issued.state }), issued.state);
check('state consume recovers nonce+verifier+returnTo', consumed.nonce === issued.nonce && !!consumed.codeVerifier && consumed.returnTo === '/admin/content');
const bad = {}; const ctxI = { ...mkCtx(), cookies: { set: (k, v) => { bad[k] = v; }, get: (k) => bad[k] } };
const iss2 = stateStore.issue(ctxI, { returnTo: '/admin', rememberMe: true });
bad['oidc_tx'] = bad['oidc_tx'].slice(0, -3) + 'zzz';
let tampered = false;
try { stateStore.consume({ ...mkCtx(), cookies: { set() {}, get: (k) => bad[k] } }, iss2.state); } catch (e) { tampered = /signature|invalid/i.test(e.message); }
check('state consume rejects tampered cookie', tampered);

// session cookie minting
const session = R('server/services/session')({ strapi });
(async () => {
  const sjar = {};
  const sctx = { request: { secure: false, ip: '1.2.3.4' }, cookies: { set: (k, v, o) => { sjar[k] = { v, o }; }, get: () => undefined } };
  const estab = await session.establishAdminSession(sctx, 42, { rememberMe: true });
  check('refresh cookie strapi_admin_refresh httpOnly path=/admin', !!sjar['strapi_admin_refresh'] && sjar['strapi_admin_refresh'].o.httpOnly === true && sjar['strapi_admin_refresh'].o.path === '/admin');
  check('establishAdminSession returns a minted access token', typeof estab.accessToken === 'string' && estab.accessToken.startsWith('access-for-'));

  // SECURITY (re-audit HIGH): logout revocation must VERIFY the refresh token, not decode-trust it
  revoked = [];
  const forgedCtx = { request: { secure: false, ip: 'x' }, cookies: { get: () => 'forged-token', set() {} } };
  const revForged = await session.invalidateByRefreshCookie(forgedCtx);
  check('SECURITY: forged refresh cookie does NOT revoke (validateRefreshToken)', revForged === false && revoked.length === 0);
  const validCtx = { request: { secure: false, ip: 'x' }, cookies: { get: () => 'valid-refresh', set() {} } };
  const revValid = await session.invalidateByRefreshCookie(validCtx);
  check('valid refresh cookie revokes only its own session (revokeSessionById)', revValid === true && revoked.length === 1 && revoked[0].sessionId === 'sid-1' && !revoked[0].all);

  // Completion binding: single-use, unguessable id -> access token
  const cid = session.stashCompletion('access-abc');
  check('stashCompletion returns an unguessable id', typeof cid === 'string' && cid.length >= 16);
  check('takeCompletion returns the token once', session.takeCompletion(cid) === 'access-abc');
  check('takeCompletion is single-use (second call null)', session.takeCompletion(cid) === null);
  check('takeCompletion unknown id -> null', session.takeCompletion('nope') === null);

  // oidc.extractRoles - realm + groups
  const oidc = R('server/services/oidc')({ strapi });
  check('extractRoles reads realm_access', oidc.extractRoles({ realm_access: { roles: ['cms-editor'] } }).includes('cms-editor'));
  pluginCfg.roleSources = ['groups'];
  const grp = oidc.extractRoles({ groups: ['/cms/editors', '/ops'] }, { });
  check('extractRoles reads groups full-path', grp.includes('/cms/editors'));
  check('extractRoles reads groups leaf name', grp.includes('editors') && grp.includes('ops'));
  pluginCfg.roleSources = ['realm'];

  const provisioning = R('server/services/provisioning')({ strapi });

  // JIT create with VERIFIED email -> ok
  mockIdentityBySubject = null; mockUserActive = true; created = null;
  const okRes = await provisioning.resolveUser({ subject: 's1', issuer: 'i', email: 'new@acme.com', emailVerified: true, firstname: 'New', lastname: 'U', idpRoles: ['cms-editor'] });
  check('resolveUser JIT (verified email) returns userId', okRes && okRes.userId === 99);
  check('created user got mapped role id 4 + isActive', created && created.roles.includes(4) && created.isActive === true);

  // SECURITY: unverified email must be refused
  mockIdentityBySubject = null; created = null;
  let unver = false;
  try { await provisioning.resolveUser({ subject: 's2', issuer: 'i', email: 'victim@acme.com', emailVerified: false, firstname: 'X', lastname: 'Y', idpRoles: ['cms-editor'] }); }
  catch (e) { unver = e.code === 'email_unverified'; }
  check('SECURITY: unverified email refused', unver);
  check('SECURITY: no user created for unverified email', created === null);

  // SECURITY: deactivated existing admin (sub match) must be denied, not reactivated
  mockIdentityBySubject = { id: 1, subject: 's3', adminUserId: 99 }; mockUserActive = false;
  let denied = false;
  try { await provisioning.resolveUser({ subject: 's3', issuer: 'i', email: 'boss@acme.com', emailVerified: true, firstname: 'B', lastname: 'O', idpRoles: ['cms-editor'] }); }
  catch (e) { denied = e.code === 'user_inactive'; }
  check('SECURITY: deactivated admin denied (no reactivation)', denied);

  // no mapped role -> deny
  mockIdentityBySubject = null; mockUserActive = true;
  let norole = false;
  try { await provisioning.resolveUser({ subject: 's4', issuer: 'i', email: 'a@acme.com', emailVerified: true, firstname: 'A', lastname: 'B', idpRoles: ['unmapped-role'] }); }
  catch (e) { norole = e.code === 'no_mapped_role'; }
  check('unmapped roles -> denied', norole);

  // Dynamic role matching (convention over configuration)
  pluginCfg.dynamicRoleMatching = { enabled: true, groupPrefix: 'cms-', matchBy: ['code', 'name'] };
  mockIdentityBySubject = null; mockUserActive = true; created = null;
  const dynRes = await provisioning.resolveUser({ subject: 's5', issuer: 'i', email: 'tr@acme.com', emailVerified: true, firstname: 'T', lastname: 'R', idpRoles: ['/cms-translators'] });
  check('dynamic: /cms-translators grants role id 7 (name match)', dynRes && created && created.roles.includes(7), created && created.roles);

  mockIdentityBySubject = null; created = null;
  let noPrefix = false;
  try { await provisioning.resolveUser({ subject: 's6', issuer: 'i', email: 'np@acme.com', emailVerified: true, firstname: 'N', lastname: 'P', idpRoles: ['translators'] }); }
  catch (e) { noPrefix = e.code === 'no_mapped_role'; }
  check('dynamic: group without prefix does NOT match', noPrefix);

  mockIdentityBySubject = null; created = null;
  let superBlocked = false;
  try { await provisioning.resolveUser({ subject: 's7', issuer: 'i', email: 'ev@acme.com', emailVerified: true, firstname: 'E', lastname: 'V', idpRoles: ['cms-strapi-super-admin'] }); }
  catch (e) { superBlocked = e.code === 'no_mapped_role'; }
  check('SECURITY: dynamic matching refuses super admin', superBlocked && created === null);
  pluginCfg.dynamicRoleMatching = { ...defaults.dynamicRoleMatching };

  // SECURITY: super-admin may not be granted by ANY SSO source unless file flag allows
  const savedMapping = pluginCfg.roleMapping;
  pluginCfg.roleMapping = { 'cms-editor': 'strapi-editor', 'boss-group': 'strapi-super-admin' };
  mockIdentityBySubject = null; created = null;
  let superMapBlocked = false;
  try { await provisioning.resolveUser({ subject: 'sm', issuer: 'i', email: 'sm@acme.com', emailVerified: true, firstname: 'S', lastname: 'M', idpRoles: ['boss-group'] }); }
  catch (e) { superMapBlocked = e.code === 'no_mapped_role'; }
  check('SECURITY: explicit roleMapping to super admin refused by default', superMapBlocked && created === null);

  pluginCfg.allowSuperAdminMapping = true;
  mockIdentityBySubject = null; created = null;
  const superOk = await provisioning.resolveUser({ subject: 'so', issuer: 'i', email: 'so@acme.com', emailVerified: true, firstname: 'S', lastname: 'O', idpRoles: ['boss-group'] });
  check('super admin granted only when file flag allowSuperAdminMapping is set', superOk && created && created.roles.includes(1));
  pluginCfg.allowSuperAdminMapping = false;
  pluginCfg.roleMapping = savedMapping;

  const savedProv = pluginCfg.provisioning;
  pluginCfg.provisioning = { ...savedProv, defaultRoleId: 1 }; // super admin as default role
  mockIdentityBySubject = null; created = null;
  let defSuperBlocked = false;
  try { await provisioning.resolveUser({ subject: 'ds', issuer: 'i', email: 'ds@acme.com', emailVerified: true, firstname: 'D', lastname: 'S', idpRoles: ['nothing-maps'] }); }
  catch (e) { defSuperBlocked = e.code === 'no_mapped_role'; }
  check('SECURITY: defaultRoleId=super admin also refused by central guard', defSuperBlocked);
  pluginCfg.provisioning = savedProv;

  // SECURITY (audit HIGH): SSO must not take over an existing super-admin by email LINK
  const savedProv2 = pluginCfg.provisioning;
  mockIdentityBySubject = null; mockUserActive = true; created = null;
  mockUserByEmail = { id: 55 }; mockUserRoles = [{ id: 1, code: 'strapi-super-admin' }];
  let linkTakeoverBlocked = false;
  try { await provisioning.resolveUser({ subject: 'newsub', issuer: 'i', email: 'boss@acme.com', emailVerified: true, firstname: 'A', lastname: 'T', idpRoles: ['cms-editor'] }); }
  catch (e) { linkTakeoverBlocked = e.code === 'email_relink_refused'; }
  check('SECURITY: email-link takeover of super-admin refused by default', linkTakeoverBlocked);

  pluginCfg.allowSuperAdminMapping = true;
  mockIdentityBySubject = null;
  const linkOk = await provisioning.resolveUser({ subject: 'newsub2', issuer: 'i', email: 'boss@acme.com', emailVerified: true, firstname: 'A', lastname: 'T', idpRoles: ['cms-editor'] });
  check('super-admin link allowed only when allowSuperAdminMapping is set', linkOk && linkOk.userId === 55);
  pluginCfg.allowSuperAdminMapping = false;
  mockUserByEmail = null; mockUserRoles = [{ id: 4, code: 'strapi-editor' }]; pluginCfg.provisioning = savedProv2;

  // Editable whitelist: prototype-pollution safety
  const editable = R('server/utils/editable');
  check('editable: hasOwnProperty key rejected (not silently accepted)', editable.validateSettings({ hasOwnProperty: 'x' }).length > 0);
  check('editable: constructor key rejected', editable.validateSettings({ constructor: 'x' }).length > 0);
  const ppKeys = JSON.parse('{"__proto__": 1, "constructor": 2}');
  let ppThrew = false; let ppErrs = [];
  try { ppErrs = editable.validateSettings(ppKeys); } catch (e) { ppThrew = true; }
  check('editable: JSON __proto__/constructor keys rejected without throwing', !ppThrew && ppErrs.length >= 1);
  check('editable: isPlainSettingsObject rejects string/array/null', !editable.isPlainSettingsObject('x') && !editable.isPlainSettingsObject([]) && !editable.isPlainSettingsObject(null) && editable.isPlainSettingsObject({}));

  // DB-backed settings: validation, precedence, reset
  const settingsSvc = strapi.plugin().service('settings');
  let valErr = null;
  try { await settingsSvc.update({ issuer: 'https://evil.example' }); } catch (e) { valErr = e; }
  check('settings: locked key (issuer) rejected', valErr && valErr.name === 'ValidationError' && /not editable/.test(valErr.message));
  valErr = null;
  try { await settingsSvc.update({ roleSources: ['bogus'] }); } catch (e) { valErr = e; }
  check('settings: bad roleSources rejected', valErr && valErr.name === 'ValidationError');
  valErr = null;
  try { await settingsSvc.update({ dynamicRoleMatching: { enabled: 'yes' } }); } catch (e) { valErr = e; }
  check('settings: wrong-typed nested value rejected', valErr && valErr.name === 'ValidationError');
  valErr = null;
  try { await settingsSvc.update('hello'); } catch (e) { valErr = e; }
  check('settings: non-object body rejected (no silent wipe)', valErr && valErr.name === 'ValidationError' && mockStore === null);
  valErr = null;
  try { await settingsSvc.update({ allowSuperAdminMapping: true }); } catch (e) { valErr = e; }
  check('settings: file-only allowSuperAdminMapping not runtime-editable', valErr && valErr.name === 'ValidationError' && /not editable/.test(valErr.message));
  // Guard-weakening flags are now file-only too
  for (const bad of [{ provisioning: { requireVerifiedEmail: false } }, { provisioning: { matchExistingByEmail: false } }, { provisioning: { allowEmailRelink: true } }, { provisioning: { reactivateDisabledOnLogin: true } }, { protectLastSuperAdmin: false }, { audit: false }, { dynamicRoleMatching: { enabled: true, allowSuperAdmin: true } }, { dynamicRoleMatching: { enabled: true, groupPrefix: '' } }]) {
    let e2 = null; try { await settingsSvc.update(bad); } catch (e) { e2 = e; }
    check('settings: rejects file-only/invalid ' + JSON.stringify(bad).slice(0, 48), e2 && e2.name === 'ValidationError');
  }
  // Tamper defense: a directly-written store row cannot smuggle a file-only nested key
  mockStore = { provisioning: { requireVerifiedEmail: false, autoCreate: false } };
  await settingsSvc.load();
  const tampered2 = R('server/utils/config').getPluginConfig(strapi);
  check('settings: mergeEditable drops tampered file-only nested key', tampered2.provisioning.requireVerifiedEmail === true && tampered2.provisioning.autoCreate === false);
  mockStore = null; await settingsSvc.load();

  await settingsSvc.update({ buttonLabel: 'From the DB', dynamicRoleMatching: { enabled: true, groupPrefix: 'x-' } });
  const merged = R('server/utils/config').getPluginConfig(strapi);
  check('settings: DB override wins over file (buttonLabel)', merged.buttonLabel === 'From the DB');
  check('settings: nested DB override deep-merges (prefix set, matchBy kept from file)',
    merged.dynamicRoleMatching.enabled === true && merged.dynamicRoleMatching.groupPrefix === 'x-' && Array.isArray(merged.dynamicRoleMatching.matchBy));
  check('settings: locked keys untouched by merge', merged.issuer === 'https://kc.example.com/realms/acme');

  await settingsSvc.update({});
  const cleared = R('server/utils/config').getPluginConfig(strapi);
  check('settings: reset {} returns to file config', cleared.buttonLabel === pluginCfg.buttonLabel && cleared.dynamicRoleMatching.enabled === false);

  const settingsCtrl = R('server/controllers/settings')({ strapi });
  check('settings controller exposes handlers', typeof settingsCtrl.getSettings === 'function' && typeof settingsCtrl.updateSettings === 'function');

  const authCtrl = R('server/controllers/auth')({ strapi });
  check('auth controller exposes handlers', ['status', 'login', 'callback', 'logout', 'backchannelLogout'].every(h => typeof authCtrl[h] === 'function'));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})();
