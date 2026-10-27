# @overpassconnect/strapi-plugin-oidc-sso

Redirect-based **OpenID Connect SSO for the Strapi v5 admin panel** - on the
**free Community Edition**. Works with **any conformant OIDC provider**.
**Verified end to end against Keycloak 26.7**; Auth0, Okta, Azure AD / Entra
ID, Authentik and Zitadel are supported through the same standard flow but not
yet independently verified (reports welcome).

Strapi's built-in admin SSO is an Enterprise feature. This plugin implements the
same outcome from the outside using the standard **OIDC Authorization Code flow
with PKCE**, and establishes a genuine Strapi admin session through Strapi's own
`SessionManager` (Strapi ≥ 5.24). Local email/password login is preserved as a
break-glass fallback.

> This is not a wrapper around the deprecated OAuth2 *password grant* (ROPC).
> Users are redirected to the identity provider, so MFA, passwordless, identity
> brokering and IdP session sharing all work.

---

## How it works

```
Admin login page
      │  click "Sign in with SSO"
      ▼
GET /oidc-sso/login
      │  mint state+nonce+PKCE, store signed HttpOnly tx cookie
      ▼
IdP /authorize  ──►  user authenticates (password, MFA, …)
      │
      ▼
GET /oidc-sso/callback?code&state
      │  1. validate state (CSRF) + TTL from tx cookie
      │  2. exchange code (+PKCE verifier) for tokens
      │  3. verify id_token (sig/iss/aud/exp/nonce) and access_token (sig/iss/azp)
      │  4. resolve/provision admin user by stable `sub`, map roles
      │  5. SessionManager.generateRefreshToken() → set `strapi_admin_refresh`
      ▼
302 → /admin/auth/login?oidc_complete=<single-use-id>&returnTo=/admin
      │  the plugin's bundled admin script (CSP-allowed, same-origin) runs:
      │   • GET /oidc-sso/complete-token?id=<id> → THIS login's access token
      │     (the id is single-use + server-held, so a planted/ambient refresh
      │      cookie can never be adopted - session-fixation defense)
      │   • write localStorage 'jwtToken' + 'isLoggedIn' (as Strapi's login does)
      │   • navigate to returnTo
      ▼
GET /admin  → SPA reads getStoredToken() → logged in → Admin dashboard
```

Why the completion bounce: the Strapi admin SPA initializes its token from
`localStorage['jwtToken']` on cold load and does **not** exchange the refresh
cookie by itself - so setting only the refresh cookie and redirecting to
`/admin` would land on the login page. The plugin therefore finishes the login
from inside the admin bundle (a `'self'` script, so it satisfies the admin CSP),
priming the exact storage Strapi's own login writes. This is verified end-to-end
against a running Strapi (see the demo harness).

---

## Support matrix

| Component | Verified | Notes |
| --------- | -------- | ----- |
| Strapi | 5.24.0 to 5.50.x | Login completion touches admin internals not covered by semver; a scheduled CI canary tests the latest Strapi twice a week. Test admin upgrades in staging. |
| Keycloak | 26.7 | Full e2e in CI: login, role and group mapping, RP-initiated logout, back-channel logout. |
| Auth0 / Okta / Azure AD / Authentik / Zitadel | conformance-based | Standard discovery + code flow + JWKS; not yet independently verified. |
| Node.js | 20, 22 | Unit suites run on both in CI. |

Multi-instance deployments need sticky sessions (completion ids and replay
caches are per-process; failure mode is a retried login, never an open door).

---

## Requirements

- **Strapi ≥ 5.24.0** (session-based admin auth; `strapi.sessionManager`).
- **Node.js ≥ 20**.
- Any OIDC provider that supports **discovery** (`/.well-known/openid-configuration`),
  the **Authorization Code flow**, and **JWKS** - Keycloak 17+, Auth0, Okta,
  Azure AD / Entra ID, Authentik, Zitadel, etc.
- A **confidential** client registration (has a client secret).
- The admin panel served over **HTTPS in production** - Strapi's admin session
  cookie is `Secure`, and browsers refuse `Secure` cookies over plain HTTP.

---

## Install

```bash
# from your Strapi app root
npm install @overpassconnect/strapi-plugin-oidc-sso
```

Or from a local checkout (recommended while you review the code):

```bash
npm install /path/to/strapi-plugin-oidc-sso
```

The plugin's config key is **`oidc-sso`** regardless of the package name (see
config below). Strapi discovers the scoped package automatically; if your
setup does not, point the plugin entry at it explicitly:

```js
// config/plugins.js
'oidc-sso': {
  enabled: true,
  resolve: '@overpassconnect/strapi-plugin-oidc-sso',
  config: { /* ... */ },
},
```

Then rebuild the admin so the login button is bundled:

```bash
npm run build && npm run develop
```

---

## Provider setup

Whatever the provider, the plugin needs four things from it:

1. A **confidential OIDC client** allowed to use the Authorization Code flow,
   with redirect URI `https://cms.example.com/oidc-sso/callback`.
2. Tokens that carry **`email` and `email_verified: true`** for admin users.
3. A claim carrying **roles or groups** to map onto Strapi admin roles
   (a `groups` claim works everywhere - see `roleSources`).
4. The **issuer URL** exactly as it appears in the tokens' `iss`.

### Keycloak (worked recipe)

1. **Create a client** in your realm:
   - Client type: **OpenID Connect**
   - Client authentication: **On** (this makes it *confidential*)
   - Standard flow: **Enabled** (Authorization Code)
   - Direct access grants: **Off** (not used; keep ROPC disabled)
2. **Valid redirect URIs**: `https://cms.example.com/oidc-sso/callback`
   (must match exactly - the plugin logs this at boot when `strapiPublicUrl` is set).
3. **Valid post logout redirect URIs**: `https://cms.example.com/admin/auth/login`
4. **Credentials** tab → copy the **Client secret**.
5. **Roles / groups → mappers (important):** Keycloak puts roles in the
   **access token**, not the ID token. Realm roles appear under
   `realm_access.roles` by default. For **client roles**, add a "client roles"
   mapper and set `roleSources: ['client']`. For **FreeIPA/LDAP groups**, add a
   **Group Membership** mapper (token claim name `groups`) and set
   `roleSources: ['groups']` - see the FreeIPA section below.
6. **Email verification:** ensure the user's `email_verified` claim is `true`
   (the User Federation / LDAP mapper for a trusted directory like FreeIPA should
   set this). The plugin refuses to link or provision by an **unverified** email.
7. (Optional) **Back-channel logout URL**:
   `https://cms.example.com/oidc-sso/backchannel-logout` to revoke Strapi
   sessions centrally when a Keycloak session ends.

### Other providers (quick notes)

- **Auth0**: Regular Web Application; issuer `https://<tenant>.<region>.auth0.com/`.
  Roles/groups need an Action adding a custom claim - set `groupsClaim` to that
  claim name and `roleSources: ['groups']`.
- **Okta**: Web app + Authorization Code. Okta's default token-endpoint auth is
  Basic - set `tokenEndpointAuthMethod: 'client_secret_basic'`. Add a `groups`
  claim to the ID token (filter as needed); `roleSources: ['groups']`.
- **Azure AD / Entra ID**: issuer `https://login.microsoftonline.com/<tenant>/v2.0`.
  Emit group memberships or app roles in the token; point `groupsClaim` at
  `groups` (or `roles` for app roles); `roleSources: ['groups']`.
- **Authentik / Zitadel**: standard discovery + code flow; expose a groups scope
  and use `roleSources: ['groups']`.
- **Opaque access tokens** (some providers): fine - when `roleSources` is
  `['groups']`, the plugin reads everything from the validated **ID token** and
  ignores an unverifiable access token. The Keycloak-shaped `realm`/`client`
  sources are the only ones that require a JWT access token.

---

## Configure Strapi

`config/plugins.js` (or `.ts`). Secrets belong in environment variables.

```js
module.exports = ({ env }) => ({
  'oidc-sso': {
    enabled: true,
    config: {
      issuer: env('OIDC_ISSUER'),          // e.g. https://kc.example.com/realms/mycompany
      clientId: env('OIDC_CLIENT_ID'),
      clientSecret: env('OIDC_CLIENT_SECRET'),

      // Public URL the browser uses to reach Strapi (for an exact redirect_uri).
      strapiPublicUrl: env('STRAPI_PUBLIC_URL'), // https://cms.example.com

      // Map IdP role/group name -> Strapi admin role id OR role code.
      roleMapping: {
        'cms-superadmin': 1,               // 1 is usually Super Admin
        'cms-editor': 'strapi-editor',
        'cms-author': 'strapi-author',
      },
      roleSources: ['realm'],              // Keycloak; use ['groups'] for other IdPs

      provisioning: {
        autoCreate: true,                  // JIT create admins on first login
        requireVerifiedEmail: true,        // takeover guard (see Security)
        matchExistingByEmail: true,        // link your existing admins on 1st login
        allowEmailRelink: false,
        reactivateDisabledOnLogin: false,  // deactivation stays a real revocation
        syncRolesOnLogin: true,
        updateProfileOnLogin: true,
      },

      protectLastSuperAdmin: true,         // never demote the final super admin
      rememberMe: true,
      rpInitiatedLogout: true,
      hideLocalLogin: false,               // keep local login visible (break-glass)
      buttonLabel: 'Sign in with SSO',     // e.g. 'Log in with Keycloak'
    },
  },
});
```

Make sure Strapi trusts your reverse proxy so HTTPS and client IPs are detected
(`config/server.js`):

```js
module.exports = ({ env }) => ({
  // ...
  proxy: { koa: true }, // or `proxy: true`
  admin: {
    auth: { secret: env('ADMIN_JWT_SECRET') },
  },
});
```

See [`config/plugins.example.js`](./config/plugins.example.js) for a fully
annotated configuration.

---

## Runtime settings UI (DB-backed)

The operational policy is also editable from the admin panel - **Settings →
OIDC SSO → Configuration** - and stored in Strapi's core store (the native
plugin-settings mechanism), no restart needed. DB values override the file for
these keys only:

`roleMapping`, `roleSources`, `groupsClaim`, `resourceRolesClient`,
`dynamicRoleMatching.{enabled,groupPrefix,matchBy}`,
`provisioning.{autoCreate,defaultRoleId,syncRolesOnLogin,updateProfileOnLogin}`,
`rememberMe`, `hideLocalLogin`, `audit`, `buttonLabel`.

Everything else is **deliberately file/env-only** and cannot be changed from a
browser session. That includes the connection/crypto settings (issuer, client
id/secret, TLS, PKCE, token validation, state signing, logout URIs) **and every
security guard** - `allowSuperAdminMapping`, `protectLastSuperAdmin`, and the
account-takeover guards `provisioning.{requireVerifiedEmail, matchExistingByEmail,
allowEmailRelink, reactivateDisabledOnLogin}`. A `settings.update` holder must
not be able to weaken a guard at runtime, so those live only in
`config/plugins.js`. Not only is writing them via the API rejected - the
read-time merge also refuses to honour them even if the store row is tampered
with directly. The page shows a **redacted subset** read-only for context
(connection basics plus the current state of every guard); secrets and TLS are
never returned by the API. Values are validated and bounded (role-map size/key
length, non-empty prefixes, enum membership).

Access is gated by two RBAC actions registered by the plugin (grant under
Settings → Roles → Plugins): *Read SSO settings* and *Update SSO settings*.
**Treat *Update SSO settings* like user/role management** - whoever holds it
controls the role mapping, and therefore who gets which admin role. One thing
they **cannot** do: grant super admin. No SSO mapping source (role mapping,
dynamic matching, or default role) may resolve to super admin unless the
**file-only** `allowSuperAdminMapping: true` is set in `config/plugins.js` - a
runtime settings-writer can never flip it, so the UI cannot be used to escalate
to super admin. Changes are audit-logged with the acting user id and apply from
the next login (multi-instance deployments converge within ~15s). "Reset to
file config" clears all DB overrides.

---

## Full configuration reference

| Key | Default | Purpose |
| --- | --- | --- |
| `issuer` | - | Provider issuer URL; must equal the tokens' `iss`. |
| `clientId` / `clientSecret` | - | Confidential client credentials. |
| `scope` | `openid email profile` | Requested scopes. |
| `strapiPublicUrl` | derived from request | Base URL for an exact `redirect_uri`. |
| `usePKCE` | `true` | PKCE S256 on the code flow. |
| `clockToleranceSeconds` | `30` | Leeway for `exp`/`iat`/`nbf`. |
| `idTokenSigningAlgs` | `['RS256']` | Allowed token algorithms (blocks `alg:none`). |
| `tokenEndpointAuthMethod` | `client_secret_post` | Or `client_secret_basic` (e.g. Okta default). |
| `discoveryTtlSeconds` | `3600` | OIDC discovery cache TTL. |
| `jwksCooldownSeconds` | `30` | Min interval between JWKS refetches. |
| `httpTimeoutMs` | `8000` | Timeout for provider calls. |
| `tlsRejectUnauthorized` | `true` | Set `false` only for internal self-signed (prefer `caCert`). |
| `caCert` | `''` | PEM of an internal CA to trust for provider TLS. |
| `roleMapping` | `{}` | IdP role/group name → Strapi role id/code. |
| `roleSources` | `['realm']` | Any of `realm`, `client`, `groups`. |
| `resourceRolesClient` | `clientId` | Client whose roles are read for `client` source. |
| `groupsClaim` | `groups` | Token claim carrying group paths for the `groups` source. |
| `dynamicRoleMatching.enabled` | `false` | Convention matching: group `${prefix}<key>` → role with that code/name. |
| `dynamicRoleMatching.groupPrefix` | `cms-` | Namespace guard for convention matching. |
| `dynamicRoleMatching.matchBy` | `['code','name']` | Match `<key>` against role `code` and/or slugified name. |
| `allowSuperAdminMapping` | `false` | **File-only.** Allow ANY SSO source to grant super admin. Keep off. |
| `provisioning.autoCreate` | `true` | JIT-create admins. |
| `provisioning.defaultRoleId` | `null` | Role for users with no mapped role/group (`null` = deny). |
| `provisioning.requireVerifiedEmail` | `true` | Require `email_verified` before any email-keyed link/provision (takeover guard). |
| `provisioning.matchExistingByEmail` | `true` | Link a pre-existing admin by verified email on first SSO login. |
| `provisioning.allowEmailRelink` | `false` | Allow a known email to bind to a new IdP subject. |
| `provisioning.reactivateDisabledOnLogin` | `false` | If false, a deactivated admin stays denied (not re-enabled by SSO). |
| `provisioning.syncRolesOnLogin` | `true` | Re-apply mapped roles every login. |
| `provisioning.updateProfileOnLogin` | `true` | Sync name/email every login. |
| `protectLastSuperAdmin` | `true` | Never strip super-admin from the last one. |
| `rememberMe` | `true` | Persistent vs session refresh cookie. |
| `rpInitiatedLogout` | `true` | End the IdP session on Strapi logout. |
| `postLogoutRedirectUri` | admin login | Where the IdP returns after logout. |
| `hideLocalLogin` | `false` | Visually de-emphasise local login (still reachable). |
| `buttonLabel` | `Sign in with SSO` | Login-page button text. |
| `stateSecret` | `admin.auth.secret` | HMAC secret for the signed state cookie. |
| `stateTtlSeconds` | `600` | Login-transaction lifetime. |
| `audit` | `true` | Log auth events (never tokens/PII). |

---

## Roles & provisioning

- **Identity is keyed on the OIDC `sub`** (stored in a hidden
  `oidc-identity` collection), so a user changing their email at the IdP
  keeps the same Strapi account.
- **First login of an existing admin**: if `matchExistingByEmail` is on and the
  IdP's **verified** email matches an existing Strapi admin, the two are
  linked - how you onboard your break-glass super admin to SSO without a duplicate.
- **Email must be verified** for any email-keyed decision (`requireVerifiedEmail`,
  default on). An unverified email is refused, preventing account takeover.
- **Subject takeover guard**: if a known email later presents a *different* `sub`,
  relinking is refused unless `allowEmailRelink: true`.
- **No mapped role/group**: refused. Set `provisioning.defaultRoleId` to a
  low-privilege role for "any authenticated IdP user gets baseline access".
- **Deactivation is real**: an admin you set inactive in Strapi stays denied on
  SSO login (not silently re-enabled) unless `reactivateDisabledOnLogin: true`.

---

## FreeIPA / LDAP groups → Keycloak → Strapi

FreeIPA exposes **groups** over LDAP, not "roles". The chain is:

```
FreeIPA group (e.g. cms-editors, LDAP)
   │  Keycloak User Federation (LDAPS) + a Group LDAP mapper
   ▼
Keycloak group  (/cms-editors)
   │  a "Group Membership" client-scope mapper adds a `groups` claim to the token
   ▼
token: { "groups": ["/cms-editors", "/ops"] , "email_verified": true }
   │  this plugin: roleSources includes 'groups'
   ▼
roleMapping: { 'cms-editors': 'strapi-editor' }  ->  Strapi admin role
```

Two ways to make FreeIPA membership drive Strapi roles:

1. **Groups (recommended, most direct):**
   - In Keycloak, federate FreeIPA over LDAPS and add a **Group LDAP mapper** so
     FreeIPA groups become Keycloak groups.
   - Add a **Group Membership** mapper on a client scope used by the Strapi
     client, claim name `groups` (turn *Full group path* on or off to taste).
   - In the plugin: `roleSources: ['groups']` and map either the full path or the
     leaf name:
     ```js
     roleSources: ['groups'],
     roleMapping: {
       '/cms-admins': 1,               // full path form
       'cms-editors': 'strapi-editor', // leaf-name form (both are matched)
     },
     ```
   The plugin adds **both** the full path (`/cms-editors`) and the leaf
   (`cms-editors`) to the match set, so either key works.

2. **Group→role in Keycloak:** map FreeIPA groups to Keycloak **realm/client roles**
   (via a Role LDAP mapper or by assigning roles to Keycloak groups). Then use
   `roleSources: ['realm']` (or `['client']`) and map the role names. Nothing
   FreeIPA-specific reaches Strapi.

Either way, the final `roleMapping` is what grants Strapi privilege - an
unmapped FreeIPA group grants nothing, so least-privilege is the default.

### Dynamic matching (no mapping table)

If you'd rather not maintain `roleMapping` per role, enable convention matching:

```js
dynamicRoleMatching: { enabled: true, groupPrefix: 'cms-' },
```

Now a FreeIPA group `cms-translators` automatically grants the Strapi role whose
`code` or slugified **name** is `translators` (e.g. a custom role named
"Translators"). Creating a new role becomes: add the role + matrix in Strapi,
create the matching `cms-<name>` group in FreeIPA - no config change, no restart.

Trade-off, stated plainly: explicit `roleMapping` is an **allow-list** (git
decides what the IdP can grant); convention matching **delegates** that decision
to whoever names groups under the prefix in FreeIPA. Guardrails: only groups
with the prefix participate, and **super admin is never grantable via SSO** - 
by any source - unless the file-only `allowSuperAdminMapping: true` is set (not
recommended). Both mechanisms can run together; results are unioned.

> **email_verified with FreeIPA:** set the Keycloak LDAP user attribute mapper so
> federated FreeIPA users have `email_verified = true` (trusted directory). Users
> without it are refused by the takeover guard.

---

## Break-glass / lockout recovery

Local login is **never disabled server-side**. If the identity provider is down
or misconfigured:

- Go directly to `/admin/auth/login` and sign in with a **local** Strapi admin
  (one that has a password). Keep at least one such account.
- To fully disable SSO, set `enabled: false` in `config/plugins.js` and restart.

If you set `hideLocalLogin: true`, the form is only hidden in the UI - a
"Use local login instead" toggle reveals it, and the endpoint still works.

---

## Logout

- **RP-initiated**: navigate to `/oidc-sso/logout` to clear the Strapi
  session cookie and end the IdP session (uses `id_token_hint`). You can
  point your own "Sign out" affordance at this URL.
- **Back-channel**: register `/oidc-sso/backchannel-logout` at the IdP to
  revoke the user's Strapi sessions when their IdP session ends elsewhere.

> Strapi's own top-bar logout revokes the Strapi session via `POST /admin/logout`
> but does not know about the IdP; use the URL above for a full single logout.

---

## Security notes

- Authorization Code + **PKCE (S256)**; `state` (CSRF) and `nonce` (replay) are
  mandatory and bound in a signed, HttpOnly, `SameSite=Lax`, short-TTL cookie on
  the Strapi origin. The PKCE verifier never travels in the `state` query param.
- ID/access tokens are verified with `jose` against the issuer's JWKS: exact issuer
  match, audience/`azp` binding, expiry with bounded clock skew, and a strict
  algorithm allow-list (no `alg:none`, no key confusion). JWKS rotation is picked
  up automatically via `kid`-miss refetch.
- Tokens, authorization codes and full claim sets are **never logged**; audit
  records carry only `sub`/`email`/`userId`/error-code.
- **Account-takeover guard**: linking/provisioning by email requires
  `email_verified=true`; a mismatched `sub` for a known email is refused.
- **Deactivation is honoured**: a disabled/blocked Strapi admin cannot log in via
  SSO and is not silently re-enabled.
- **Least privilege**: an unmapped IdP role/group grants nothing; the last
  active super admin can never be demoted by role sync.
- Same-origin redirects (error/logout) are **relative**, so a spoofed `Host`
  header cannot turn them into an open redirect.
- Open-redirect protection on `returnTo` (only app-relative `/admin` paths).
- The transaction cookie is single-use (cleared on callback, success or fail);
  forced JWKS refetches are throttled against amplification.
- Basic per-instance rate limiting on `login`/`callback`.
- **Deploy over HTTPS with `proxy: { koa: true }`** so the `Secure` session
  cookie is set; the plugin warns at boot if this looks misconfigured.
- **Logout revokes the server-side session**, not just the cookie, so a captured
  refresh cookie stops working after logout. The refresh token is **verified via
  the SessionManager** (signature + active session) before revocation and only
  its own session is revoked - a forged/unsigned cookie revokes nothing. The
  endpoint is rate-limited, and cross-site navigations (Sec-Fetch-Site) skip
  revocation to avoid a forced-logout CSRF.
- **Login completion is bound to a single-use, server-held id** issued by the
  callback (not to any ambient refresh cookie), so a pre-existing/planted refresh
  cookie cannot be adopted (session-fixation defense). `audit` is file/env-only so
  a settings-writer cannot disable the audit trail.
- **Super admin is protected on two axes**: it can neither be *granted* by any
  SSO mapping source nor *seized* by email-linking an SSO identity to an existing
  super-admin account, unless the file-only `allowSuperAdminMapping` is set.
- **Spec conformance:** all provider endpoints are required to be `https`
  (localhost excepted); the RFC 9207 `iss` authorization-response param is checked
  when present; the ID-token `azp` is verified whenever it is present (not only
  for multi-audience tokens); the `openid` scope and `Bearer` token_type are
  asserted; the JWKS algorithm is pinned to the key's own `alg`.
- **Cookies:** every cookie the plugin sets (`strapi_admin_refresh`, `oidc_tx`,
  `oidc_idh`) is `Secure` in production regardless of proxy header detection, and
  the id-token-hint cookie's lifetime is tied to the session.
- **Back-channel logout:** the logout token is fully validated (signature, `iss`,
  `aud`, `iat`, `jti`, no `nonce`, `events` object) with `jti` replay rejection;
  it resolves the account by `sub` or `sid` and revokes that user's sessions.
- Outbound provider calls are bounded (2 MB response cap, wall-clock deadline);
  identity lookups are scoped by `(issuer, subject)`; emails are NFKC-normalized
  before matching.

### Known limitations (low)

- **Auto-provisioning scale**: with `provisioning.defaultRoleId` set, every
  authenticated IdP principal is provisioned an admin. Leave `defaultRoleId: null`
  (deny) unless you intend "any directory user gets baseline access", and prefer
  gating on a mapped role/group.
- **Concurrency**: JIT provisioning and the last-super-admin check are not wrapped
  in a single locking transaction; simultaneous first-logins of the *same* subject
  are handled (idempotent upsert), but pathological concurrent role-syncs of
  multiple super admins could race. Low likelihood; `protectLastSuperAdmin`
  (file-only) is the backstop.
- **Multi-instance settings**: a runtime settings change propagates to other
  instances within the ~15s cache TTL, and the `jti` replay cache is per-instance.
  For immediate fleet-wide behaviour, restart or rely on file config.
- **Multi-instance login completion**: the single-use completion id is held
  in-memory per instance, so multi-instance deployments need sticky sessions (or
  a single instance) for the callback and the `/oidc-sso/complete-token` redeem
  to land on the same node. If they don't, completion fails **closed** (login
  errors, no security impact) and the user retries - it never fails open.
- **Back-channel `sid` logout** revokes *all* of the resolved user's sessions
  rather than a single session, because an OP `sid` cannot be mapped to one Strapi
  session id. Safe direction (over-revokes), and only relevant if your IdP is
  configured for session-scoped back-channel logout.
- **`rememberMe: false` + the login-completion step**: the completion always
  writes the access token to `localStorage['jwtToken']` (where the admin SPA
  reads it), whereas vanilla Strapi routes a non-remembered token to a session
  cookie. This is a *persistence* difference, not an exposure one - both sinks
  are same-origin-JS-readable, so XSS risk is identical, and the token is
  short-lived and inert once the session-scoped refresh cookie is gone after
  browser close. The default (`rememberMe: true`) matches Strapi exactly.

---

## Troubleshooting

**"Discovery issuer mismatch" at boot / login.** The provider's `iss` differs
from your `issuer` config - almost always an IdP behind a proxy advertising a
different hostname. For Keycloak, fix `KC_HOSTNAME` so realm URLs match; in
general, set `issuer` to exactly what appears in a decoded token's `iss`.

**Login succeeds but bounces back to the login page.** The `strapi_admin_refresh`
cookie was not stored/sent. Check: admin served over HTTPS in prod; Strapi has
`proxy` enabled; `admin.auth.cookie.domain`/`path` not misconfigured; the browser
isn't blocking the cookie.

**"No mapped role."** The user's IdP roles/groups don't match `roleMapping`, or
the claim isn't in the token. Verify the provider's mappers and `roleSources`.
Decode the token at jwt.io to see which claims actually arrive.

**Access token rejected but login should work.** If your provider issues opaque
(non-JWT) access tokens, use `roleSources: ['groups']` - the plugin then relies
on the validated ID token and tolerates the opaque access token.

**Button doesn't appear on the login page.** Rebuild the admin (`npm run build`).
If your Strapi minor changed the login markup, use the host-app override below.

**Self-signed internal IdP.** Prefer `caCert` (PEM string) over
`tlsRejectUnauthorized: false`.

---

## Host-app override for the button (optional, guaranteed)

The bundled button attaches via a resilient DOM injector, which needs no host
changes. If you'd rather render it through Strapi's own admin entry, add this to
`src/admin/app.tsx` and skip the injector:

```tsx
// src/admin/app.tsx
export default {
  config: {
    // The endpoint is stable regardless of Strapi's login markup:
    // window.location.href = '/oidc-sso/login?returnTo=/admin'
  },
  bootstrap() {},
};
```

The only stable contract you depend on is the URL
`/oidc-sso/login?returnTo=/admin` - link or redirect to it however you like.

---

## Testing

```bash
npm test          # 63 logic + 17 crypto tests, no app or network needed
npm run test:e2e  # end-to-end suite against a running app + IdP
```

The e2e suite runs about 95 checks against a real Keycloak, counting the
database rows and provider calls each login causes and injecting provider
faults (refused, hung or garbage token responses, unreachable signing keys).
It is documented, with its bundled mock IdP and TLS front, in
[CONTRIBUTING.md](CONTRIBUTING.md). CI runs the unit suites on Node 20/22 and
the e2e suite in develop and production mode on every push, plus a
twice-weekly canary against the latest Strapi release.

## Security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Please do not open
public issues for anything exploitable.

## License

MIT © dev@overpassconnect.com
