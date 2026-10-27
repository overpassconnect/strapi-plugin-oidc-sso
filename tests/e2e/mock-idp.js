'use strict';
/* Minimal local OIDC provider for exercising strapi-plugin-oidc-sso end to end.
   Serves discovery, JWKS, authorize (auto-approves a fixed demo user), token
   (RS256 id+access tokens, PKCE S256 verified), and end_session. */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const jose = require('jose');

const PORT = Number(process.env.MOCK_IDP_PORT || 9000);
const ISSUER = `http://localhost:${PORT}`;
const CLIENT_ID = 'strapi-admin';
const CLIENT_SECRET = 'demo-secret';
const KID = 'mock-key-1';

// Fixed demo user + authorizations. realm_access.roles drives Strapi role mapping.
const USER = {
  sub: 'mock-user-1',
  sid: 'mock-sid-1',
  email: 'demo@localhost',
  email_verified: true,
  name: 'Demo User',
  given_name: 'Demo',
  family_name: 'User',
  realm_access: { roles: ['cms-editor'] },
};

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const codes = new Map(); // code -> { nonce, code_challenge, redirect_uri }

let priv, pub, jwk;

async function init() {
  const kp = await jose.generateKeyPair('RS256');
  priv = kp.privateKey;
  pub = kp.publicKey;
  jwk = { ...(await jose.exportJWK(pub)), kid: KID, alg: 'RS256', use: 'sig' };
}

async function idToken(nonce) {
  return new jose.SignJWT({
    email: USER.email,
    email_verified: USER.email_verified,
    name: USER.name,
    given_name: USER.given_name,
    family_name: USER.family_name,
    nonce,
    sid: USER.sid,
    azp: CLIENT_ID,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setSubject(USER.sub)
    .setAudience(CLIENT_ID)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(priv);
}

async function accessToken() {
  return new jose.SignJWT({ azp: CLIENT_ID, realm_access: USER.realm_access, email: USER.email })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(ISSUER)
    .setSubject(USER.sub)
    .setAudience('account')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(priv);
}

function send(res, status, obj, headers = {}) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, ISSUER);
  const p = u.pathname;
  try {
    if (p === '/.well-known/openid-configuration') {
      return send(res, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        end_session_endpoint: `${ISSUER}/logout`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'email', 'profile'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (p === '/jwks') {
      return send(res, 200, { keys: [jwk] });
    }
    if (p === '/authorize') {
      const q = u.searchParams;
      const code = b64url(crypto.randomBytes(24));
      codes.set(code, {
        nonce: q.get('nonce'),
        code_challenge: q.get('code_challenge'),
        redirect_uri: q.get('redirect_uri'),
      });
      const back = new URL(q.get('redirect_uri'));
      back.searchParams.set('code', code);
      if (q.get('state')) back.searchParams.set('state', q.get('state'));
      back.searchParams.set('iss', ISSUER); // RFC 9207
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (p === '/token' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', async () => {
        const form = new URLSearchParams(body);
        const code = form.get('code');
        const rec = codes.get(code);
        if (!rec) return send(res, 400, { error: 'invalid_grant' });
        codes.delete(code);
        // PKCE S256 check
        if (rec.code_challenge) {
          const verifier = form.get('code_verifier') || '';
          const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
          if (challenge !== rec.code_challenge) return send(res, 400, { error: 'invalid_grant', error_description: 'PKCE mismatch' });
        }
        return send(res, 200, {
          access_token: await accessToken(),
          id_token: await idToken(rec.nonce),
          token_type: 'Bearer',
          expires_in: 300,
        });
      });
      return;
    }
    if (p === '/logout') {
      const post = u.searchParams.get('post_logout_redirect_uri');
      if (post) {
        res.writeHead(302, { location: post });
        return res.end();
      }
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'not_found', path: p });
  } catch (err) {
    return send(res, 500, { error: 'server_error', message: err.message });
  }
});

init().then(() => {
  server.listen(PORT, () => console.log(`[mock-idp] listening on ${ISSUER} (client=${CLIENT_ID}, user=${USER.email}, roles=${USER.realm_access.roles})`));
});
