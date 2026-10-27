'use strict';
/**
 * End-to-end admin SSO tests over plain HTTP(S), no browser needed.
 * Drives a running Strapi app (with this plugin) against a running IdP.
 *
 * Env:
 *   STRAPI_URL        default http://localhost:1337 (an https URL is verified against E2E_CA_FILE)
 *   IDP               'keycloak' (default) or 'mock' (tests/e2e/mock-idp.js, which auto-authorizes)
 *   KC_URL, KC_REALM, KC_ADMIN_USER, KC_ADMIN_PASS, E2E_CLIENT_ID
 *                     same names and defaults as kc-realm-setup.js
 *   E2E_PASS          password of the realm's test users (default Passw0rd!demo)
 *   E2E_ADMIN_EMAIL, E2E_ADMIN_PASS
 *                     local Strapi super admin (break-glass), for the settings scenarios
 *                     (defaults e2e-admin@example.com / E2e-Admin-Passw0rd)
 *   E2E_SQLITE        the app's sqlite file: enables row counts (admin users, identities, sessions)
 *   E2E_APP_DIR       app root used to load better-sqlite3 (default: two levels above E2E_SQLITE)
 *   E2E_OUTBOUND_LOG  log written by tests/e2e/outbound-tap.js: enables provider-call counts
 *   E2E_FAULT_FILE    fault file read by tests/e2e/outbound-tap.js: enables the fault scenarios
 *   E2E_CA_FILE       PEM to trust for an https STRAPI_URL (e.g. a local TLS front proxy)
 *   E2E_DIRECT_URL    the app's own plain-HTTP address behind that proxy: checks that a
 *                     production instance reached without TLS fails closed
 *   E2E_EXPECT_EMAIL  (mock) default demo@localhost
 *
 * Scenarios that need an optional input are reported as SKIP, never as PASS.
 * The suite restores every Keycloak and settings change it makes, so it can be
 * re-run against the same app and realm.
 */
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const crypto = require('crypto');

const STRAPI = (process.env.STRAPI_URL || 'http://localhost:1337').replace(/\/+$/, '');
const IDP = process.env.IDP || 'keycloak';
const KC = (process.env.KC_URL || 'http://127.0.0.1:8080').replace(/\/+$/, '');
const REALM = process.env.KC_REALM || 'strapi-demo';
const KC_ADMIN_USER = process.env.KC_ADMIN_USER || 'admin';
const KC_ADMIN_PASS = process.env.KC_ADMIN_PASS || 'admin';
const CLIENT_ID = process.env.E2E_CLIENT_ID || 'strapi-admin';
const PASS = process.env.E2E_PASS || 'Passw0rd!demo';
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'e2e-admin@example.com';
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'E2e-Admin-Passw0rd';
const SQLITE = process.env.E2E_SQLITE || '';
const APP_DIR = process.env.E2E_APP_DIR || (SQLITE ? path.resolve(path.dirname(SQLITE), '..') : '');
const OUTBOUND = process.env.E2E_OUTBOUND_LOG || '';
const FAULT = process.env.E2E_FAULT_FILE || '';
const CA = process.env.E2E_CA_FILE ? fs.readFileSync(process.env.E2E_CA_FILE) : null;
const DIRECT = (process.env.E2E_DIRECT_URL || '').replace(/\/+$/, '');
const EXPECT_MOCK_EMAIL = process.env.E2E_EXPECT_EMAIL || 'demo@localhost';
const IDP_ORIGIN = new URL(KC).origin;

const editorEmail = 'editor.demo@example.com';

// ---------------------------------------------------------------------------
// Reporting

let pass = 0, fail = 0, skip = 0;
const ok = (n, c, extra) => {
  if (c) { pass++; console.log('PASS', n); }
  else { fail++; console.log('FAIL', n, extra || ''); }
};
const skipped = (n, why) => { skip++; console.log('SKIP', n, `(${why})`); };
const note = (msg) => console.log('   ' + msg);

async function scenario(name, fn) {
  console.log(`\n== ${name}`);
  try {
    await fn();
  } catch (err) {
    fail++;
    console.log('FAIL', `${name}: threw`, err && err.stack ? err.stack.split('\n').slice(0, 3).join(' | ') : err);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const safeJson = (s) => { try { return JSON.parse(s); } catch (e) { return null; } };

// ---------------------------------------------------------------------------
// HTTP: forces IPv4 for localhost (Node resolves it to ::1 while many servers
// bind IPv4 only) but keeps the Host header; https is verified against E2E_CA_FILE.

function req(url, { method = 'GET', headers = {}, body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const opts = {
      method,
      hostname: u.hostname === 'localhost' ? '127.0.0.1' : u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers: { host: u.host, ...headers },
      timeout: timeoutMs,
    };
    if (isHttps && CA) opts.ca = CA;
    // Always frame a body: Node sends a DELETE body without Content-Length or
    // chunking, and its bytes then corrupt the next request on the kept-alive
    // connection (seen as a bare 400 from Keycloak).
    if (body && opts.headers['content-length'] === undefined) opts.headers['content-length'] = Buffer.byteLength(body);
    const r = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (d) => (data += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on('timeout', () => r.destroy(new Error(`timed out: ${method} ${url}`)));
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

/** Per-host cookie jars, so IdP and Strapi cookies never bleed into each other. */
function makeJars() {
  const jars = new Map();
  const jarFor = (url) => {
    const host = new URL(url).host;
    if (!jars.has(host)) jars.set(host, {});
    return jars.get(host);
  };
  const absorb = (url, res) => {
    const jar = jarFor(url);
    for (const line of res.headers['set-cookie'] || []) {
      const [pair] = line.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const val = pair.slice(i + 1).trim();
      if (val === '') delete jar[name]; else jar[name] = val;
    }
  };
  const header = (url) => Object.entries(jarFor(url)).map(([k, v]) => `${k}=${v}`).join('; ');
  return { jarFor, absorb, header };
}

const setsCookie = (res, name) =>
  (res.headers['set-cookie'] || []).some((l) => l.startsWith(`${name}=`) && !l.startsWith(`${name}=;`));
const cookieLine = (res, name) =>
  (res.headers['set-cookie'] || []).find((l) => l.startsWith(`${name}=`) && !l.startsWith(`${name}=;`)) || '';

// The plugin throttles /login and /callback at 30 per minute per IP. Pace the
// suite under that so it never trips its own limiter (the limiter itself is
// asserted last).
const hits = { login: [], cb: [] };
async function paced(kind, fn) {
  for (;;) {
    const now = Date.now();
    const q = hits[kind];
    while (q.length && now - q[0] > 60000) q.shift();
    if (q.length < 25) break;
    const waitMs = 60000 - (now - q[0]) + 250;
    note(`pacing ${kind} for ${Math.ceil(waitMs / 1000)}s to stay under the plugin's rate limit`);
    await sleep(waitMs);
  }
  hits[kind].push(Date.now());
  return fn();
}

// ---------------------------------------------------------------------------
// Side effects: database rows (sqlite) and provider calls (outbound tap)

let db = null;
function getDb() {
  if (!SQLITE) return null;
  if (!db) {
    const Database = require(require.resolve('better-sqlite3', { paths: [APP_DIR] }));
    db = new Database(SQLITE, { readonly: true, fileMustExist: true, timeout: 5000 });
  }
  return db;
}
const scalar = (sql, ...params) => {
  const d = getDb();
  return d ? d.prepare(sql).get(...params).n : null;
};
const count = {
  users: (email) => scalar('SELECT COUNT(*) AS n FROM admin_users WHERE email = ?', email),
  identities: (email) => scalar('SELECT COUNT(*) AS n FROM oidc_identities WHERE email = ?', email),
  activeSessions: (email) =>
    scalar(
      "SELECT COUNT(*) AS n FROM strapi_sessions s JOIN admin_users u ON u.id = s.user_id WHERE u.email = ? AND s.status = 'active'",
      email
    ),
};
const userIdOf = (email) => {
  const d = getDb();
  if (!d) return null;
  const row = d.prepare('SELECT id FROM admin_users WHERE email = ?').get(email);
  return row ? row.id : null;
};
const latestSessionIdOf = (email) => {
  const d = getDb();
  if (!d) return null;
  const row = d
    .prepare(
      "SELECT s.session_id AS sid FROM strapi_sessions s JOIN admin_users u ON u.id = s.user_id WHERE u.email = ? AND s.status = 'active' ORDER BY s.id DESC LIMIT 1"
    )
    .get(email);
  return row ? row.sid : null;
};

function outboundMark() {
  if (!OUTBOUND) return null;
  try { return fs.statSync(OUTBOUND).size; } catch (e) { return 0; }
}
/** Provider calls the Strapi process made since `mark`, grouped by endpoint kind. */
function outboundSince(mark) {
  if (mark === null) return null;
  let buf;
  try { buf = fs.readFileSync(OUTBOUND); } catch (e) { buf = Buffer.alloc(0); }
  const kinds = { token: 0, certs: 0, discovery: 0, userinfo: 0, other: 0 };
  for (const line of buf.subarray(mark).toString('utf8').split('\n')) {
    if (!line) continue;
    const e = safeJson(line);
    if (!e || !e.url.startsWith(IDP_ORIGIN)) continue;
    if (e.url.includes('/protocol/openid-connect/token')) kinds.token++;
    else if (e.url.includes('/protocol/openid-connect/certs')) kinds.certs++;
    else if (e.url.includes('/.well-known/openid-configuration')) kinds.discovery++;
    else if (e.url.includes('/userinfo')) kinds.userinfo++;
    else kinds.other++;
  }
  return kinds;
}

const armFault = (spec) => fs.writeFileSync(FAULT, JSON.stringify(spec));
const faultPending = () => fs.existsSync(FAULT);

// ---------------------------------------------------------------------------
// Keycloak admin API (admin-cli tokens live 60s, so they are refreshed)

let kcTok = null;
async function kcToken() {
  if (kcTok && Date.now() < kcTok.exp) return kcTok.value;
  const r = await req(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: 'admin-cli', grant_type: 'password', username: KC_ADMIN_USER, password: KC_ADMIN_PASS,
    }).toString(),
  });
  if (r.status !== 200) throw new Error(`Keycloak admin token: HTTP ${r.status}`);
  const j = JSON.parse(r.body);
  kcTok = { value: j.access_token, exp: Date.now() + (j.expires_in - 15) * 1000 };
  return kcTok.value;
}
async function kc(method, p, body) {
  const headers = { authorization: `Bearer ${await kcToken()}` };
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await req(`${KC}/admin/realms/${REALM}${p}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : null,
  });
  if (r.status >= 300) throw new Error(`Keycloak ${method} ${p}: HTTP ${r.status} ${r.body.slice(0, 200)}`);
  return { status: r.status, location: r.headers.location || '', json: safeJson(r.body) };
}
const kcUserId = async (username) => {
  const users = (await kc('GET', `/users?username=${encodeURIComponent(username)}&exact=true`)).json;
  if (!users || !users[0]) throw new Error(`Keycloak user ${username} not found (realm provisioned?)`);
  return users[0].id;
};
const kcRealmRole = async (name) => (await kc('GET', `/roles/${encodeURIComponent(name)}`)).json;
const kcClient = async () => {
  const list = (await kc('GET', `/clients?clientId=${encodeURIComponent(CLIENT_ID)}`)).json;
  const client = (await kc('GET', `/clients/${list[0].id}`)).json;
  // Never write the secret back: some Keycloak versions return it masked, and an
  // update without the field keeps the stored one.
  delete client.secret;
  return client;
};
async function kcEnsureGroup(name) {
  const found = ((await kc('GET', `/groups?search=${encodeURIComponent(name)}&exact=true`)).json || [])
    .find((g) => g.name === name);
  if (found) return found.id;
  const created = await kc('POST', '/groups', { name });
  return created.location.split('/').pop();
}

// ---------------------------------------------------------------------------
// Local Strapi super admin (break-glass), for settings and RBAC checks

let adminJwt = null;
async function strapiAdmin(method, p, body) {
  if (!adminJwt) {
    const r = await req(`${STRAPI}/admin/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASS }),
    });
    if (r.status !== 200) throw new Error(`local super admin login: HTTP ${r.status} (create it, see CONTRIBUTING.md)`);
    adminJwt = JSON.parse(r.body).data.token;
  }
  const headers = { authorization: `Bearer ${adminJwt}` };
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await req(`${STRAPI}${p}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : null });
  return { status: r.status, json: safeJson(r.body) };
}
const getOverrides = async () => {
  const r = await strapiAdmin('GET', '/oidc-sso/settings');
  if (r.status !== 200) throw new Error(`GET /oidc-sso/settings as super admin: HTTP ${r.status}`);
  return r.json.data.overrides || {};
};
const putOverrides = async (overrides) => {
  const r = await strapiAdmin('PUT', '/oidc-sso/settings', overrides);
  if (r.status !== 200) throw new Error(`PUT /oidc-sso/settings: HTTP ${r.status} ${JSON.stringify(r.json)}`);
};

// ---------------------------------------------------------------------------
// Login primitives

/** Authenticate at the IdP; returns the redirect Location back to the callback. */
async function authenticateAtIdp(authorizeUrl, jars, username, password) {
  if (IDP === 'mock') {
    const authz = await req(authorizeUrl, { headers: { cookie: jars.header(authorizeUrl) } });
    jars.absorb(authorizeUrl, authz);
    if (authz.status !== 302) throw new Error(`mock authorize: expected 302, got ${authz.status}`);
    return authz.headers.location;
  }
  const page = await req(authorizeUrl, { headers: { cookie: jars.header(authorizeUrl) } });
  jars.absorb(authorizeUrl, page);
  if (page.status === 302) return page.headers.location; // an IdP session already exists
  if (page.status !== 200) throw new Error(`Keycloak authorize: expected 200 login page, got ${page.status}`);
  const m = page.body.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/);
  if (!m) throw new Error('Keycloak login form not found in the authorize response');
  const action = m[1].replace(/&amp;/g, '&');
  const post = await req(action, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jars.header(action) },
    body: new URLSearchParams({ username, password, credentialId: '' }).toString(),
  });
  jars.absorb(action, post);
  if (post.status !== 302) {
    throw new Error(`Keycloak credential POST: expected 302, got ${post.status} (wrong password or realm not provisioned?)`);
  }
  return post.headers.location;
}

/** Up to (not including) the callback: returns what a browser would hold at that moment. */
async function startLogin(username, jars = makeJars()) {
  const login = await paced('login', () => req(`${STRAPI}/oidc-sso/login`, { headers: { cookie: jars.header(STRAPI) } }));
  jars.absorb(STRAPI, login);
  if (login.status !== 302) throw new Error(`/oidc-sso/login: expected 302, got ${login.status}`);
  const txCookie = jars.jarFor(STRAPI)['oidc_tx'] || null;
  const location = await authenticateAtIdp(login.headers.location, jars, username, PASS);
  const callbackUrl = new URL(location, STRAPI).toString();
  if (!callbackUrl.includes('/oidc-sso/callback')) throw new Error(`IdP did not redirect to the callback: ${location}`);
  return { jars, txCookie, txLine: cookieLine(login, 'oidc_tx'), callbackUrl };
}

/** Fire the callback (optionally with an explicit Cookie header) and decode the outcome. */
async function finishLogin(started, { cookie } = {}) {
  const sendCookie = cookie !== undefined ? cookie : started.jars.header(STRAPI);
  const t0 = Date.now();
  const cb = await paced('cb', () => req(started.callbackUrl, { headers: sendCookie ? { cookie: sendCookie } : {} }));
  const elapsedMs = Date.now() - t0;
  started.jars.absorb(STRAPI, cb);
  const location = cb.headers.location || '';
  return {
    status: cb.status,
    location,
    elapsedMs,
    completionId: (location.match(/[?&]oidc_complete=([A-Za-z0-9_-]+)/) || [])[1] || null,
    error: (location.match(/[?&]sso_error=([a-z_]+)/) || [])[1] || null,
    setRefresh: setsCookie(cb, 'strapi_admin_refresh'),
    refreshLine: cookieLine(cb, 'strapi_admin_refresh'),
    idhLine: cookieLine(cb, 'oidc_idh'),
  };
}

async function redeem(completionId) {
  const r = await req(`${STRAPI}/oidc-sso/complete-token?id=${encodeURIComponent(completionId)}`);
  const j = safeJson(r.body);
  return { status: r.status, token: (j && j.data && j.data.token) || null };
}

async function me(token) {
  const r = await req(`${STRAPI}/admin/users/me`, { headers: { authorization: `Bearer ${token}` } });
  const j = safeJson(r.body);
  const data = (j && j.data) || {};
  return { status: r.status, email: data.email, roles: (data.roles || []).map((x) => x.code).sort() };
}

/** Exchange the jar's refresh cookie for an access token (rotates the cookie). */
async function exchange(jars) {
  const before = jars.jarFor(STRAPI)['strapi_admin_refresh'];
  const r = await req(`${STRAPI}/admin/access-token`, {
    method: 'POST',
    headers: { cookie: jars.header(STRAPI), 'content-type': 'application/json' },
    body: '{}',
  });
  jars.absorb(STRAPI, r);
  const j = safeJson(r.body);
  return {
    status: r.status,
    token: (j && j.data && j.data.token) || null,
    rotated: !!jars.jarFor(STRAPI)['strapi_admin_refresh'] && jars.jarFor(STRAPI)['strapi_admin_refresh'] !== before,
  };
}

/** A complete login: returns the started state, the callback outcome and the access token. */
async function fullLogin(username) {
  const started = await startLogin(username);
  const done = await finishLogin(started);
  const token = done.completionId ? (await redeem(done.completionId)).token : null;
  return { ...started, ...done, token };
}

// ---------------------------------------------------------------------------

(async () => {
  console.log(`e2e against ${STRAPI} with IdP=${IDP}; row counts ${SQLITE ? 'on' : 'off'}, ` +
    `call counts ${OUTBOUND ? 'on' : 'off'}, fault injection ${FAULT ? 'on' : 'off'}`);

  // A previous run may have finished with the rate-limit scenario.
  const probe = await req(`${STRAPI}/oidc-sso/login`);
  if (probe.status === 429) {
    note('login endpoint still throttled from a previous run; waiting 61s');
    await sleep(61000);
  }

  await scenario('Public status and unauthenticated settings', async () => {
    const st = await req(`${STRAPI}/oidc-sso/status`);
    const j = safeJson(st.body) || {};
    ok('status endpoint up with loginPath', st.status === 200 && j.loginPath === '/oidc-sso/login', `status=${st.status}`);
    const putUnauth = await req(`${STRAPI}/oidc-sso/settings`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"buttonLabel":"x"}',
    });
    ok('settings PUT without auth is 401', putUnauth.status === 401, `got ${putUnauth.status}`);
    const getUnauth = await req(`${STRAPI}/oidc-sso/settings`);
    ok('settings GET without auth is 401', getUnauth.status === 401, `got ${getUnauth.status}`);
  });

  if (IDP === 'mock') {
    await scenario('Mock IdP login', async () => {
      const l = await fullLogin('demo');
      ok('login set signed oidc_tx cookie (cleared after use)', !!l.txCookie && !l.jars.jarFor(STRAPI)['oidc_tx']);
      ok('callback set strapi_admin_refresh', l.setRefresh);
      ok('callback redirects with an oidc_complete id', !!l.completionId, `loc=${l.location}`);
      const second = l.completionId ? await redeem(l.completionId) : { status: 0 };
      ok('completion id is single-use (second redemption 404)', second.status === 404, `got ${second.status}`);
      const who = l.token ? await me(l.token) : {};
      ok(`access token belongs to ${EXPECT_MOCK_EMAIL}`, who.status === 200 && who.email === EXPECT_MOCK_EMAIL,
        `status=${who.status} email=${who.email}`);
    });
    return finish();
  }

  const restoreActions = [];
  let editorLogin = null;

  if (DIRECT) {
    await scenario('Production reached over plain HTTP fails closed', async () => {
      const r = await paced('login', () => req(`${DIRECT}/oidc-sso/login`));
      ok('login is refused with sso_error=session_failed (a server misconfiguration, not an IdP error)',
        r.status === 302 && /[?&]sso_error=session_failed/.test(r.headers.location || ''), `status=${r.status} loc=${r.headers.location}`);
      ok('no cookie is set', !(r.headers['set-cookie'] || []).length, JSON.stringify(r.headers['set-cookie']));
    });
  }

  await scenario('Editor login (realm role) with side-effect counts', async () => {
    const usersBefore = count.users(editorEmail);
    const sessionsBefore = count.activeSessions(editorEmail);
    const mark = outboundMark();
    const l = await fullLogin('editor.demo');
    editorLogin = l;
    ok('login set signed oidc_tx cookie (cleared after use)', !!l.txCookie && !l.jars.jarFor(STRAPI)['oidc_tx']);
    ok('callback set strapi_admin_refresh', l.setRefresh);
    ok('callback set the oidc_idh cookie for RP-initiated logout', !!l.jars.jarFor(STRAPI)['oidc_idh']);
    const overHttps = STRAPI.startsWith('https:');
    for (const [name, line] of [['oidc_tx', l.txLine], ['strapi_admin_refresh', l.refreshLine], ['oidc_idh', l.idhLine]]) {
      const attrs = line.toLowerCase().split(';').map((s) => s.trim());
      ok(`${name} cookie is HttpOnly and SameSite=Lax`, attrs.includes('httponly') && attrs.includes('samesite=lax'), line);
      ok(`${name} cookie is ${overHttps ? '' : 'not '}Secure when served over ${overHttps ? 'https' : 'http'}`,
        attrs.includes('secure') === overHttps, line);
    }
    ok('callback redirects to the login page with an oidc_complete id', !!l.completionId, `loc=${l.location}`);
    ok('completion id redeems for an access token', !!l.token);
    const again = l.completionId ? await redeem(l.completionId) : { status: 0 };
    ok('completion id is single-use (second redemption 404)', again.status === 404, `got ${again.status}`);
    const forged = await redeem(crypto.randomBytes(24).toString('base64url'));
    ok('a forged completion id is refused (404)', forged.status === 404, `got ${forged.status}`);
    const who = l.token ? await me(l.token) : {};
    ok('access token belongs to editor.demo with exactly the Editor role',
      who.status === 200 && who.email === editorEmail && JSON.stringify(who.roles) === '["strapi-editor"]',
      `status=${who.status} email=${who.email} roles=${JSON.stringify(who.roles)}`);
    if (SQLITE) {
      ok('exactly one admin user exists for editor.demo afterwards', count.users(editorEmail) === 1,
        `before=${usersBefore} after=${count.users(editorEmail)}`);
      ok('exactly one identity row exists for editor.demo', count.identities(editorEmail) === 1,
        `rows=${count.identities(editorEmail)}`);
      ok('the login added exactly one active session', count.activeSessions(editorEmail) === sessionsBefore + 1,
        `before=${sessionsBefore} after=${count.activeSessions(editorEmail)}`);
    } else skipped('row counts for the editor login', 'E2E_SQLITE not set');
    const calls = outboundSince(mark);
    if (calls) {
      ok('the login made exactly one token call', calls.token === 1, JSON.stringify(calls));
      ok('discovery was served from cache (no discovery call)', calls.discovery === 0, JSON.stringify(calls));
      ok('at most one signing-key (JWKS) fetch', calls.certs <= 1, JSON.stringify(calls));
      ok('no other provider calls', calls.userinfo === 0 && calls.other === 0, JSON.stringify(calls));
    } else skipped('provider-call counts for the editor login', 'E2E_OUTBOUND_LOG not set');
  });

  await scenario('Plugin-created sessions survive Strapi refresh-token rotation', async () => {
    if (!editorLogin) throw new Error('needs the editor login');
    const first = await exchange(editorLogin.jars);
    ok('access-token exchange succeeds and rotates the refresh cookie', first.status === 200 && first.rotated,
      `status=${first.status} rotated=${first.rotated}`);
    const second = await exchange(editorLogin.jars);
    ok('the rotated refresh cookie exchanges again', second.status === 200, `status=${second.status}`);
    const who = second.token ? await me(second.token) : {};
    ok('the renewed access token still belongs to editor.demo', who.status === 200 && who.email === editorEmail,
      `status=${who.status}`);
  });

  await scenario('Groups claim mapping (author.demo via /cms-authors)', async () => {
    const l = await fullLogin('author.demo');
    const who = l.token ? await me(l.token) : {};
    ok('author.demo gets exactly the Author role from the groups claim',
      who.status === 200 && JSON.stringify(who.roles) === '["strapi-author"]',
      `status=${who.status} roles=${JSON.stringify(who.roles)} error=${l.error}`);
  });

  for (const [user, code] of [['unverified.demo', 'email_unverified'], ['nobody.demo', 'no_mapped_role']]) {
    await scenario(`Refusal: ${user} -> ${code}`, async () => {
      const email = `${user}@example.com`;
      const before = { users: count.users(email), ids: count.identities(email) };
      const started = await startLogin(user);
      const done = await finishLogin(started);
      ok(`refused with sso_error=${code}`, done.error === code, `loc=${done.location}`);
      ok('refusal sets no session cookie', !done.setRefresh);
      if (SQLITE) {
        ok('refusal provisions no admin user and no identity',
          count.users(email) === before.users && count.identities(email) === before.ids && count.users(email) === 0,
          `users ${before.users}->${count.users(email)} identities ${before.ids}->${count.identities(email)}`);
      } else skipped('row counts for the refusal', 'E2E_SQLITE not set');
    });
  }

  await scenario('Settings RBAC and immediate cache refresh', async () => {
    if (!editorLogin || !editorLogin.token) throw new Error('needs the editor login');
    const asEditor = (method, body) => req(`${STRAPI}/oidc-sso/settings`, {
      method,
      headers: { authorization: `Bearer ${editorLogin.token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : null,
    });
    // The editor token from the first login was renewed by rotation; fetch a fresh one.
    const fresh = await exchange(editorLogin.jars);
    if (fresh.token) editorLogin.token = fresh.token;
    ok('an SSO editor cannot read the settings (403)', (await asEditor('GET')).status === 403);
    ok('an SSO editor cannot write the settings (403)', (await asEditor('PUT', { buttonLabel: 'pwned' })).status === 403);
    const saved = await getOverrides();
    const label = `E2E label ${Date.now()}`;
    try {
      await putOverrides({ ...saved, buttonLabel: label });
      const st = safeJson((await req(`${STRAPI}/oidc-sso/status`)).body) || {};
      ok('a super-admin settings write is visible at once on the public status endpoint', st.buttonLabel === label,
        `label=${st.buttonLabel}`);
    } finally {
      await putOverrides(saved);
    }
  });

  await scenario('Role sync on re-login with dynamic matching (Editor -> Author -> Editor)', async () => {
    const uid = await kcUserId('editor.demo');
    const editorRole = await kcRealmRole('cms-editor');
    const gid = await kcEnsureGroup('cms-author');
    const saved = await getOverrides();
    try {
      await kc('DELETE', `/users/${uid}/role-mappings/realm`, [editorRole]);
      await kc('PUT', `/users/${uid}/groups/${gid}`);
      await putOverrides({
        ...saved,
        roleMapping: {},
        dynamicRoleMatching: { enabled: true, groupPrefix: 'cms-', matchBy: ['code', 'name'] },
      });
      const usersBefore = count.users(editorEmail);
      const l = await fullLogin('editor.demo');
      const who = l.token ? await me(l.token) : {};
      ok('group cms-author grants Author by convention and replaces Editor',
        who.status === 200 && JSON.stringify(who.roles) === '["strapi-author"]',
        `status=${who.status} roles=${JSON.stringify(who.roles)} error=${l.error}`);
      if (SQLITE) {
        ok('the existing admin user was updated, not duplicated', count.users(editorEmail) === usersBefore,
          `before=${usersBefore} after=${count.users(editorEmail)}`);
      }
    } finally {
      await kc('POST', `/users/${uid}/role-mappings/realm`, [editorRole]);
      await kc('DELETE', `/users/${uid}/groups/${gid}`);
      await putOverrides(saved);
    }
    const back = await fullLogin('editor.demo');
    const whoBack = back.token ? await me(back.token) : {};
    ok('after restoring Keycloak and settings, the next login syncs back to Editor',
      JSON.stringify(whoBack.roles) === '["strapi-editor"]', `roles=${JSON.stringify(whoBack.roles)}`);
  });

  await scenario('RP-initiated logout ends the Strapi and the Keycloak session', async () => {
    const l = await fullLogin('editor.demo');
    const out = await req(`${STRAPI}/oidc-sso/logout`, { headers: { cookie: l.jars.header(STRAPI) } });
    l.jars.absorb(STRAPI, out);
    const endSession = out.headers.location || '';
    ok('logout redirects to the Keycloak end_session endpoint with id_token_hint',
      out.status === 302 && endSession.startsWith(`${KC}/realms/${REALM}/protocol/openid-connect/logout`) &&
        endSession.includes('id_token_hint='), `status=${out.status} loc=${endSession.slice(0, 120)}`);
    const kcOut = await req(endSession, { headers: { cookie: l.jars.header(endSession) } });
    l.jars.absorb(endSession, kcOut);
    ok('Keycloak ends its session and returns to the Strapi login page',
      kcOut.status === 302 && (kcOut.headers.location || '').startsWith(`${STRAPI}/admin/auth/login`),
      `status=${kcOut.status} loc=${kcOut.headers.location}`);
    const ex = await exchange(l.jars);
    ok('the old refresh cookie no longer exchanges (server-side session revoked)', ex.status === 401, `status=${ex.status}`);
    const meAfter = await me(l.token);
    ok('the old access token is refused at once', meAfter.status === 401, `status=${meAfter.status}`);
    const again = await paced('login', () => req(`${STRAPI}/oidc-sso/login`));
    const authz = await req(again.headers.location, { headers: { cookie: l.jars.header(again.headers.location) } });
    ok('Keycloak asks for credentials again (no silent re-login)', authz.status === 200 && /kc-form-login/.test(authz.body),
      `status=${authz.status}`);
  });

  await scenario('Back-channel logout revokes at once, and its token cannot be replayed', async () => {
    const l = await fullLogin('editor.demo');
    const client = await kcClient();
    const originalUrl = client.attributes['backchannel.logout.url'];
    const captured = [];
    const capture = http.createServer((inReq, inRes) => {
      let body = '';
      inReq.on('data', (d) => (body += d));
      inReq.on('end', async () => {
        const fwd = await req(`${STRAPI}/oidc-sso/backchannel-logout`, {
          method: 'POST',
          headers: { 'content-type': inReq.headers['content-type'] || 'application/x-www-form-urlencoded' },
          body,
        });
        captured.push({ body, status: fwd.status });
        inRes.writeHead(fwd.status, { 'content-type': 'application/json' });
        inRes.end(fwd.body);
      });
    });
    await new Promise((r) => capture.listen(0, '127.0.0.1', r));
    const captureUrl = `http://127.0.0.1:${capture.address().port}/bcl`;
    try {
      await kc('PUT', `/clients/${client.id}`, {
        ...client, attributes: { ...client.attributes, 'backchannel.logout.url': captureUrl },
      });
      await kc('POST', `/users/${await kcUserId('editor.demo')}/logout`);
      for (let i = 0; i < 50 && captured.length === 0; i++) await sleep(200);
      ok('Keycloak delivered a back-channel logout token and the plugin accepted it (200)',
        captured.length > 0 && captured[0].status === 200, `captured=${JSON.stringify(captured.map((c) => c.status))}`);
      ok('the refresh cookie no longer exchanges', (await exchange(l.jars)).status === 401);
      ok('the access token is refused at once', (await me(l.token)).status === 401);
      if (captured[0]) {
        const replay = await req(`${STRAPI}/oidc-sso/backchannel-logout`, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: captured[0].body,
        });
        ok('replaying the same logout token is rejected (jti replay, 400)', replay.status === 400, `status=${replay.status}`);
      }
    } finally {
      const now = await kcClient();
      await kc('PUT', `/clients/${now.id}`, {
        ...now, attributes: { ...now.attributes, 'backchannel.logout.url': originalUrl },
      });
      capture.close();
    }
  });

  await scenario('Logout cannot be forged or forced cross-site', async () => {
    const l = await fullLogin('editor.demo');
    const victimSid = latestSessionIdOf(editorEmail);
    const forgedPayload = { userId: String(userIdOf(editorEmail) || 1), sessionId: victimSid || 'unknown', type: 'refresh', exp: Math.floor(Date.now() / 1000) + 3600 };
    const forged = [
      Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify(forgedPayload)).toString('base64url'),
      crypto.randomBytes(32).toString('base64url'),
    ].join('.');
    const out = await req(`${STRAPI}/oidc-sso/logout`, { headers: { cookie: `strapi_admin_refresh=${forged}` } });
    ok('logout with a forged refresh cookie still redirects', out.status === 302, `status=${out.status}`);
    ok('the forged cookie revoked nothing (the real session still exchanges)', (await exchange(l.jars)).status === 200);
    const cross = await req(`${STRAPI}/oidc-sso/logout`, {
      headers: { cookie: l.jars.header(STRAPI), 'sec-fetch-site': 'cross-site' },
    });
    ok('a cross-site logout navigation redirects', cross.status === 302, `status=${cross.status}`);
    ok('a cross-site logout navigation does not revoke the session', (await exchange(l.jars)).status === 200);
  });

  await scenario('Callback replay and state tampering', async () => {
    const usersBefore = count.users(editorEmail);
    const started = await startLogin('editor.demo');
    const done = await finishLogin(started);
    ok('the original callback succeeds', !!done.completionId, `loc=${done.location}`);
    const sessionsAfterFirst = count.activeSessions(editorEmail);

    let mark = outboundMark();
    const noTx = await finishLogin(started);
    ok('replaying the callback without the (consumed) tx cookie is refused with state_invalid', noTx.error === 'state_invalid',
      `loc=${noTx.location}`);
    const callsNoTx = outboundSince(mark);
    if (callsNoTx) ok('that replay made no provider call', callsNoTx.token === 0, JSON.stringify(callsNoTx));

    mark = outboundMark();
    const withTx = await finishLogin(started, { cookie: `oidc_tx=${started.txCookie}` });
    ok('replaying with the original tx cookie is refused (Keycloak rejects the used code)',
      withTx.error === 'code_exchange_failed', `loc=${withTx.location}`);
    const callsWithTx = outboundSince(mark);
    if (callsWithTx) ok('that replay made exactly one (rejected) token call', callsWithTx.token === 1, JSON.stringify(callsWithTx));
    ok('neither replay set a session cookie', !noTx.setRefresh && !withTx.setRefresh);

    const tampered = await startLogin('editor.demo');
    const u = new URL(tampered.callbackUrl);
    u.searchParams.set('state', `${u.searchParams.get('state')}x`);
    mark = outboundMark();
    const bad = await finishLogin({ ...tampered, callbackUrl: u.toString() });
    ok('a tampered state parameter is refused with state_invalid', bad.error === 'state_invalid', `loc=${bad.location}`);
    const callsBad = outboundSince(mark);
    if (callsBad) ok('the tampered callback made no provider call', callsBad.token === 0, JSON.stringify(callsBad));

    if (SQLITE) {
      ok('replays and tampering created no session and no user',
        count.activeSessions(editorEmail) === sessionsAfterFirst && count.users(editorEmail) === usersBefore,
        `sessions ${sessionsAfterFirst}->${count.activeSessions(editorEmail)} users ${usersBefore}->${count.users(editorEmail)}`);
    }
  });

  await scenario('Concurrent first login of the same new user', async () => {
    const username = `race${Date.now()}.demo`;
    const email = `${username}@example.com`;
    const created = await kc('POST', '/users', {
      username, email, emailVerified: true, enabled: true, firstName: 'Race', lastName: 'Demo',
      credentials: [{ type: 'password', value: PASS, temporary: false }],
    });
    const raceId = created.location.split('/').pop();
    restoreActions.push(() => kc('DELETE', `/users/${raceId}`));
    await kc('POST', `/users/${raceId}/role-mappings/realm`, [await kcRealmRole('cms-editor')]);
    const [a, b] = [await startLogin(username), await startLogin(username)];
    const [ra, rb] = await Promise.all([finishLogin(a), finishLogin(b)]);
    note(`outcomes: ${ra.completionId ? 'ok' : ra.error} / ${rb.completionId ? 'ok' : rb.error}`);
    ok('at least one of the two concurrent first logins succeeds', !!(ra.completionId || rb.completionId));
    ok('neither concurrent callback crashed (both answered with a redirect)', ra.status === 302 && rb.status === 302,
      `${ra.status}/${rb.status}`);
    if (SQLITE) {
      ok('exactly one admin user was provisioned', count.users(email) === 1, `admin users=${count.users(email)}`);
      ok('exactly one identity row was written', count.identities(email) === 1, `identities=${count.identities(email)}`);
    } else skipped('duplicate check for the concurrent first login', 'E2E_SQLITE not set');
  });

  if (FAULT) {
    const cases = [
      { mode: 'refuse', expect: 'provider_unreachable', maxMs: 5000 },
      { mode: 'hang', expect: 'provider_unreachable', minMs: 7000, maxMs: 15000 },
      { mode: 'garbage', expect: 'code_exchange_failed', maxMs: 5000 },
      { mode: 'status', status: 500, expect: 'code_exchange_failed', maxMs: 5000 },
    ];
    for (const c of cases) {
      await scenario(`Provider fault at the token endpoint: ${c.mode}${c.status ? ` ${c.status}` : ''}`, async () => {
        const sessionsBefore = count.activeSessions(editorEmail);
        const started = await startLogin('editor.demo');
        armFault({ match: '/protocol/openid-connect/token', mode: c.mode, status: c.status, count: 1 });
        const done = await finishLogin(started);
        ok('the injected fault was consumed', !faultPending());
        ok(`the login fails with sso_error=${c.expect}`, done.error === c.expect, `got ${done.error} (${done.location})`);
        ok(`it fails in a bounded time (${done.elapsedMs} ms)`,
          done.elapsedMs <= c.maxMs && (!c.minMs || done.elapsedMs >= c.minMs), `elapsed=${done.elapsedMs}`);
        ok('no session cookie is set', !done.setRefresh);
        if (SQLITE) ok('no session is created', count.activeSessions(editorEmail) === sessionsBefore);
      });
    }

    await scenario('Signing-key rotation, and an unreachable JWKS during rotation', async () => {
      const realm = (await kc('GET', '')).json;
      // Keycloak signs with the highest-priority active key, so each added key
      // must outrank the previous one to force a key id the plugin has not seen.
      let priority = 10000;
      const addKey = async (name) => {
        priority += 100;
        const r = await kc('POST', '/components', {
          name, providerId: 'rsa-generated', providerType: 'org.keycloak.keys.KeyProvider', parentId: realm.id,
          config: { priority: [String(priority)], enabled: ['true'], active: ['true'], algorithm: ['RS256'], keySize: ['2048'] },
        });
        const id = r.location.split('/').pop();
        restoreActions.push(() => kc('DELETE', `/components/${id}`));
        return id;
      };
      await addKey(`e2e-rotated-${Date.now()}`);
      let mark = outboundMark();
      const first = await fullLogin('editor.demo');
      ok('login succeeds right after Keycloak rotates its signing key', !!first.token, `error=${first.error}`);
      const c1 = outboundSince(mark);
      if (c1) ok('the unknown key id triggered exactly one JWKS refetch', c1.certs === 1, JSON.stringify(c1));
      mark = outboundMark();
      const second = await fullLogin('editor.demo');
      ok('the next login succeeds too', !!second.token, `error=${second.error}`);
      const c2 = outboundSince(mark);
      if (c2) ok('and uses the cached keys (no JWKS fetch)', c2.certs === 0, JSON.stringify(c2));

      await sleep(5500); // past the plugin's 5s throttle on forced JWKS refetches
      await addKey(`e2e-rotated-${Date.now()}`);
      const started = await startLogin('editor.demo');
      armFault({ match: '/protocol/openid-connect/certs', mode: 'refuse', count: 2 });
      const done = await finishLogin(started);
      fs.rmSync(FAULT, { force: true });
      ok('with the JWKS unreachable, the login fails with sso_error=provider_unreachable',
        done.error === 'provider_unreachable', `got ${done.error}`);
      ok('and sets no session cookie', !done.setRefresh);
    });
  } else {
    skipped('provider fault scenarios', 'E2E_FAULT_FILE not set');
  }

  for (const undo of restoreActions.reverse()) {
    try { await undo(); } catch (e) { note(`cleanup step failed: ${e.message}`); }
  }

  await scenario('Login endpoint rate limit (runs last: it throttles this IP for a minute)', async () => {
    let throttledAt = 0;
    for (let i = 1; i <= 40; i++) {
      const r = await req(`${STRAPI}/oidc-sso/login`);
      if (r.status === 429) {
        throttledAt = i;
        ok('the throttled response says too_many_requests', (safeJson(r.body) || {}).error === 'too_many_requests');
        break;
      }
    }
    ok('the login endpoint throttles within 31 requests a minute', throttledAt > 0 && throttledAt <= 31,
      `first 429 at request ${throttledAt || 'never'}`);
  });

  return finish();
})().catch((e) => {
  console.error('THREW', e && e.stack ? e.stack : e);
  process.exit(2);
});

function finish() {
  if (db) db.close();
  console.log(`\n=== ${pass} passed, ${fail} failed, ${skip} skipped ===`);
  process.exit(fail === 0 ? 0 : 1);
}
