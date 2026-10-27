'use strict';
/**
 * Provision the e2e realm on a local Keycloak via the Admin REST API.
 * Idempotent: deletes an existing realm of the same name first.
 *
 * Env (all optional):
 *   KC_URL            default http://127.0.0.1:8080
 *   KC_ADMIN_USER     default admin
 *   KC_ADMIN_PASS     default admin
 *   KC_REALM          default strapi-demo
 *   E2E_CLIENT_ID     default strapi-admin
 *   E2E_CLIENT_SECRET default kc-local-demo-secret-51c9e2b7a4
 *   E2E_USER_PASS     default Passw0rd!demo
 *   STRAPI_URL        default http://localhost:1337  (redirect/backchannel target)
 *   E2E_BACKCHANNEL_URL  default ${STRAPI_URL}/oidc-sso/backchannel-logout; set it when
 *                     Keycloak must reach Strapi directly (e.g. STRAPI_URL is a TLS
 *                     front with a certificate Keycloak does not trust)
 *
 * Fixture matrix:
 *   client  strapi-admin   confidential, PKCE S256, backchannel logout URL,
 *                          Group Membership mapper -> `groups` claim (full path)
 *   role    cms-editor     realm role (map to Strapi `strapi-editor`)
 *   group   /cms-authors   groups-claim path (map to Strapi `strapi-author`)
 *   users   editor.demo    verified, role cms-editor
 *           author.demo    verified, group /cms-authors
 *           unverified.demo UNVERIFIED, role cms-editor  -> must be refused
 *           nobody.demo    verified, nothing             -> no_mapped_role
 */
const KC = process.env.KC_URL || 'http://127.0.0.1:8080';
const ADMIN = {
  username: process.env.KC_ADMIN_USER || 'admin',
  password: process.env.KC_ADMIN_PASS || 'admin',
};
const REALM = process.env.KC_REALM || 'strapi-demo';
const CLIENT_ID = process.env.E2E_CLIENT_ID || 'strapi-admin';
const CLIENT_SECRET = process.env.E2E_CLIENT_SECRET || 'kc-local-demo-secret-51c9e2b7a4';
const PASSWORD = process.env.E2E_USER_PASS || 'Passw0rd!demo';
const STRAPI = (process.env.STRAPI_URL || 'http://localhost:1337').replace(/\/+$/, '');
const BACKCHANNEL_URL = process.env.E2E_BACKCHANNEL_URL || `${STRAPI}/oidc-sso/backchannel-logout`;

async function adminToken() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: 'admin-cli',
      grant_type: 'password',
      username: ADMIN.username,
      password: ADMIN.password,
    }),
  });
  if (!res.ok) throw new Error(`admin token: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

function user(username, { verified = true, roles = [], groups = [] } = {}) {
  return {
    username,
    email: `${username}@example.com`,
    emailVerified: verified,
    enabled: true,
    firstName: username.split('.')[0].replace(/^./, (c) => c.toUpperCase()),
    lastName: 'Demo',
    credentials: [{ type: 'password', value: PASSWORD, temporary: false }],
    realmRoles: roles,
    groups,
  };
}

const realmJson = {
  realm: REALM,
  enabled: true,
  sslRequired: 'external',
  registrationAllowed: false,
  roles: {
    realm: [
      { name: 'cms-editor', description: 'Maps to Strapi Editor' },
      { name: 'totally-unrelated', description: 'Never mapped; noise for extraction' },
    ],
  },
  groups: [{ name: 'cms-authors', path: '/cms-authors' }],
  users: [
    user('editor.demo', { roles: ['cms-editor', 'totally-unrelated'] }),
    user('author.demo', { groups: ['/cms-authors'] }),
    user('unverified.demo', { verified: false, roles: ['cms-editor'] }),
    user('nobody.demo', {}),
  ],
  clients: [
    {
      clientId: CLIENT_ID,
      name: 'Strapi Admin SSO (e2e)',
      enabled: true,
      publicClient: false,
      secret: CLIENT_SECRET,
      protocol: 'openid-connect',
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      serviceAccountsEnabled: false,
      redirectUris: [`${STRAPI}/oidc-sso/callback`],
      webOrigins: [STRAPI],
      attributes: {
        'pkce.code.challenge.method': 'S256',
        'backchannel.logout.url': BACKCHANNEL_URL,
        'backchannel.logout.session.required': 'true',
        'post.logout.redirect.uris': `${STRAPI}/*`,
      },
      protocolMappers: [
        {
          name: 'groups',
          protocol: 'openid-connect',
          protocolMapper: 'oidc-group-membership-mapper',
          consentRequired: false,
          config: {
            'claim.name': 'groups',
            'full.path': 'true',
            'id.token.claim': 'true',
            'access.token.claim': 'true',
            'userinfo.token.claim': 'true',
          },
        },
      ],
    },
  ],
};

(async () => {
  const token = await adminToken();
  const hdrs = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

  const del = await fetch(`${KC}/admin/realms/${REALM}`, { method: 'DELETE', headers: hdrs });
  console.log(`delete old realm: ${del.status}${del.status === 404 ? ' (none)' : ''}`);

  const create = await fetch(`${KC}/admin/realms`, {
    method: 'POST',
    headers: hdrs,
    body: JSON.stringify(realmJson),
  });
  if (create.status !== 201) throw new Error(`create realm: ${create.status} ${await create.text()}`);
  console.log(`realm created: ${REALM}`);

  const disc = await fetch(`${KC}/realms/${REALM}/.well-known/openid-configuration`);
  const d = await disc.json();
  console.log(`discovery issuer: ${d.issuer}`);
  console.log('SETUP_OK');
})().catch((e) => {
  console.error('SETUP_FAILED', e.message);
  process.exit(1);
});
