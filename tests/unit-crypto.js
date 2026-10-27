'use strict';
/* Verify the real jose-based token validation path with a genuine RSA keypair,
   stubbing only the network (discovery + JWKS). */

const path = require('path');
const DIR = path.resolve(__dirname, "..");
const P = (p) => path.join(DIR, p);

const jose = require('jose');

const ISSUER = 'https://kc.example.com/realms/acme';
const CLIENT = 'strapi-admin';
const JWKS_URI = `${ISSUER}/protocol/openid-connect/certs`;

let pass = 0, fail = 0;
const check = (n, c, x) => { if (c) { pass++; console.log('PASS', n); } else { fail++; console.log('FAIL', n, x !== undefined ? JSON.stringify(x) : ''); } };

(async () => {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
  const jwk = { ...(await jose.exportJWK(publicKey)), kid: 'test-kid', alg: 'RS256', use: 'sig' };

  // Stub the http util BEFORE requiring oidc (oidc destructures at load time).
  // `outage` makes the named endpoint fail the way an unreachable host does.
  const outage = { jwks: false, token: false };
  const refused = () => Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8080'), { code: 'ECONNREFUSED' });
  const http = require(P('server/utils/http'));
  http.postForm = async () => {
    if (outage.token) throw refused();
    return { status: 400, json: { error: 'invalid_grant' } };
  };
  http.getJson = async (url) => {
    if (outage.jwks && url === JWKS_URI) throw refused();
    if (url.endsWith('/.well-known/openid-configuration')) {
      return {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
        token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
        jwks_uri: JWKS_URI,
        end_session_endpoint: `${ISSUER}/protocol/openid-connect/logout`,
      };
    }
    if (url === JWKS_URI) return { keys: [jwk] };
    throw new Error('unexpected url ' + url);
  };

  const strapi = {
    log: { info() {}, warn() {}, error() {} },
    config: { get: (k, d) => (k === 'plugin::oidc-sso' ? {
      issuer: ISSUER, clientId: CLIENT, clientSecret: 's',
      roleSources: ['realm'], clockToleranceSeconds: 30, idTokenSigningAlgs: ['RS256'],
      usePKCE: true, scope: 'openid email profile',
      discoveryTtlSeconds: 3600, jwksCooldownSeconds: 30, httpTimeoutMs: 8000, tlsRejectUnauthorized: true,
    } : d) },
  };
  const oidc = require(P('server/services/oidc'))({ strapi });

  const sign = (claims, { alg = 'RS256', kid = 'test-kid', exp = '5m', aud = CLIENT } = {}) =>
    new jose.SignJWT(claims)
      .setProtectedHeader({ alg, kid })
      .setIssuer(ISSUER).setSubject('kc-sub-1').setAudience(aud)
      .setIssuedAt().setExpirationTime(exp)
      .sign(privateKey);

  // --- ID token: happy path ---
  const idToken = await sign({ nonce: 'NONCE123', email: 'boss@acme.com', given_name: 'B', family_name: 'Oss' });
  const idClaims = await oidc.validateIdToken(idToken, { nonce: 'NONCE123' });
  check('valid id_token accepted', idClaims.sub === 'kc-sub-1' && idClaims.email === 'boss@acme.com');

  // --- ID token: nonce mismatch ---
  let bad = false;
  try { await oidc.validateIdToken(idToken, { nonce: 'WRONG' }); } catch (e) { bad = /nonce/i.test(e.message); }
  check('id_token wrong nonce rejected', bad);

  // --- ID token: tampered signature ---
  bad = false;
  const tampered = idToken.slice(0, -4) + (idToken.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
  try { await oidc.validateIdToken(tampered, { nonce: 'NONCE123' }); } catch (e) { bad = true; }
  check('id_token tampered signature rejected', bad);

  // --- ID token: expired ---
  bad = false;
  const expired = await sign({ nonce: 'N' }, { exp: '-1m' });
  try { await oidc.validateIdToken(expired, { nonce: 'N' }); } catch (e) { bad = /exp|invalid/i.test(e.message); }
  check('expired id_token rejected', bad);

  // --- ID token: wrong audience ---
  bad = false;
  const wrongAud = await sign({ nonce: 'N' }, { aud: 'someone-else' });
  try { await oidc.validateIdToken(wrongAud, { nonce: 'N' }); } catch (e) { bad = true; }
  check('id_token wrong audience rejected', bad);

  // --- Access token: happy path (aud=account, azp=client) ---
  const accessToken = await sign({ azp: CLIENT, realm_access: { roles: ['cms-editor', 'cms-boss'] } }, { aud: 'account' });
  const accessClaims = await oidc.validateAccessToken(accessToken);
  check('valid access_token accepted (azp binding)', accessClaims.azp === CLIENT);
  check('extractRoles from access_token', oidc.extractRoles(accessClaims).includes('cms-editor'));

  // --- Access token: not bound to our client ---
  bad = false;
  const foreign = await sign({ azp: 'other', realm_access: { roles: [] } }, { aud: 'account' });
  try { await oidc.validateAccessToken(foreign); } catch (e) { bad = /client|azp|aud/i.test(e.message); }
  check('access_token foreign client rejected', bad);

  // --- Access token: azp mismatch on single-aud ID token rejected ---
  bad = false;
  const badAzp = await sign({ nonce: 'N', azp: 'evil-client' });
  try { await oidc.validateIdToken(badAzp, { nonce: 'N' }); } catch (e) { bad = /azp/i.test(e.message); }
  check('id_token azp mismatch (single aud) rejected', bad);

  // --- Logout token validation (now requires jti + iat) ---
  const mkLogout = (jti) => new jose.SignJWT({ events: { 'http://schemas.openid.net/event/backchannel-logout': {} }, jti })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
    .setIssuer(ISSUER).setSubject('kc-sub-1').setAudience(CLIENT).setIssuedAt().setExpirationTime('5m')
    .sign(privateKey);
  const lt = await oidc.validateLogoutToken(await mkLogout('jti-1'));
  check('valid logout_token accepted', lt.sub === 'kc-sub-1');

  // replay of the same jti is rejected
  bad = false;
  try { await oidc.validateLogoutToken(await mkLogout('jti-1')); } catch (e) { bad = /replay|jti/i.test(e.message); }
  check('logout_token replay (same jti) rejected', bad);

  // missing jti rejected
  bad = false;
  try { await oidc.validateLogoutToken(await mkLogout(undefined)); } catch (e) { bad = /jti/i.test(e.message); }
  check('logout_token without jti rejected', bad);

  bad = false;
  const notLogout = await sign({}, {}); // no events claim
  try { await oidc.validateLogoutToken(notLogout); } catch (e) { bad = /event/i.test(e.message); }
  check('logout_token without event rejected', bad);

  // --- Authorization URL construction ---
  const url = await oidc.buildAuthorizationUrl({ redirectUri: 'https://cms.example.com/keycloak-sso/callback', state: 'st', nonce: 'no', codeChallenge: 'cc' });
  const u = new URL(url);
  check('authorize url has PKCE + params',
    u.searchParams.get('code_challenge') === 'cc' &&
    u.searchParams.get('code_challenge_method') === 'S256' &&
    u.searchParams.get('response_type') === 'code' &&
    u.searchParams.get('client_id') === CLIENT &&
    u.searchParams.get('state') === 'st' &&
    u.searchParams.get('nonce') === 'no');

  // --- Provider outages read as outages, never as a failed or forged sign-in ---
  let code = null;
  try { await oidc.exchangeCode({ code: 'c', redirectUri: 'https://cms.example.com/oidc-sso/callback', codeVerifier: 'v' }); } catch (e) { code = e.code; }
  check('token endpoint answering an error -> code_exchange_failed', code === 'code_exchange_failed', code);
  outage.token = true;
  code = null;
  try { await oidc.exchangeCode({ code: 'c', redirectUri: 'https://cms.example.com/oidc-sso/callback', codeVerifier: 'v' }); } catch (e) { code = e.code; }
  outage.token = false;
  check('unreachable token endpoint -> provider_unreachable', code === 'provider_unreachable', code);

  const coldOidc = require(P('server/services/oidc'))({ strapi }); // empty JWKS cache
  outage.jwks = true;
  code = null;
  try { await coldOidc.validateIdToken(await sign({ nonce: 'N' }), { nonce: 'N' }); } catch (e) { code = e.code; }
  outage.jwks = false;
  check('unreachable JWKS endpoint -> provider_unreachable', code === 'provider_unreachable', code);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('THREW', e); process.exit(2); });
