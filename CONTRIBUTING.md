# Contributing

Thanks for considering a contribution. This plugin authenticates admin users,
so the bar for changes is deliberately high: every change needs tests, and
anything touching the auth flow needs an e2e run.

## Development setup

```bash
git clone https://github.com/overpassconnect/strapi-plugin-oidc-sso
cd strapi-plugin-oidc-sso
npm install
npm test
```

`npm test` runs the two unit suites (no network, no Strapi app needed):

- `tests/unit-logic.js` exercises the server graph against a mocked Strapi:
  routes, config validator, PKCE, redirect guards, state-store signing,
  session establishment, provisioning policy, super-admin chokepoints, and
  the settings whitelist.
- `tests/unit-crypto.js` exercises real token validation with a genuine RSA
  keypair, stubbing only the network.

## End-to-end testing

The e2e suite (`tests/e2e/flow.js`) drives a running Strapi app with this
plugin installed, over plain HTTP(S) with no browser: logins for realm roles
and groups claims, refusals, role sync and dynamic matching, settings RBAC,
RP-initiated and back-channel logout (including token replay), forged and
cross-site logout, callback replay and state tampering, concurrent first
logins, provider faults, signing-key rotation, and the rate limiter. It
restores every Keycloak and settings change it makes, so it can be re-run.

Fastest loop, with the bundled mock IdP (no Java or Docker; login only):

```bash
node tests/e2e/mock-idp.js &
# point your dev app's plugin config at issuer http://localhost:9000, then:
IDP=mock node tests/e2e/flow.js
```

Full fidelity, against a real Keycloak:

```bash
# 1. Run Keycloak locally (Docker shown; a plain distribution works too).
#    Host networking lets its back-channel logout calls reach your app.
docker run -d --network host \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.8.1 start-dev --http-port 8080

# 2. Provision the test realm (idempotent)
STRAPI_URL=http://127.0.0.1:1337 npm run test:e2e:setup-realm

# 3. Point your app at issuer http://127.0.0.1:8080/realms/strapi-demo with
#    the client from the realm script (use 127.0.0.1 consistently: the issuer
#    follows the request host in dev mode, and Node resolves localhost to ::1),
#    and create the local super admin the settings scenarios use:
npx strapi admin:create-user --email=e2e-admin@example.com \
  --password=E2e-Admin-Passw0rd --firstname=E2E --lastname=Admin

# 4. Start the app with the outbound tap preloaded, so the suite can count
#    provider calls and inject provider faults:
NODE_OPTIONS="--require /path/to/plugin/tests/e2e/outbound-tap.js" \
  E2E_OUTBOUND_LOG=/tmp/e2e/outbound.log E2E_FAULT_FILE=/tmp/e2e/fault.json \
  npm run develop

# 5. Run the suite with the same two files, plus the app's sqlite file for
#    row counts (each optional input left out turns its checks into SKIP)
STRAPI_URL=http://127.0.0.1:1337 E2E_SQLITE=/path/to/app/.tmp/data.db \
  E2E_OUTBOUND_LOG=/tmp/e2e/outbound.log E2E_FAULT_FILE=/tmp/e2e/fault.json \
  npm run test:e2e
```

Production mode runs the same suite through `tests/e2e/tls-front.js`, a
TLS-terminating stand-in for nginx or HAProxy: build the admin with
`NODE_ENV=production npm run build`, set `proxy: { koa: true }` in the app's
`config/server.js`, start the app with `strapi start`, start the front with a
self-signed certificate for 127.0.0.1, and run the suite with
`STRAPI_URL=https://127.0.0.1:8443 E2E_CA_FILE=<cert> E2E_DIRECT_URL=http://127.0.0.1:1337`.
`.github/workflows/e2e.yml` is the exact recipe for both modes.

CI runs the unit suites on every push and the full suite in both modes on a
scaffolded Strapi app with the plugin installed from its packed tarball; a
scheduled canary repeats it against the latest Strapi release to catch
upstream admin-internal changes.

## Ground rules

- No new runtime dependencies without prior discussion (`jose` is currently
  the only one).
- Security-guard settings stay file/env-only. Do not move them into the
  runtime-editable whitelist; see the reasoning in `server/utils/editable.js`.
- Never log tokens, secrets, or unescaped attacker-controlled strings.
- Update `CHANGELOG.md` with user-visible changes.
- For anything exploitable, follow [SECURITY.md](SECURITY.md) instead of
  opening a public issue.
