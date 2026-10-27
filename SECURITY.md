# Security Policy

This plugin performs authentication for the Strapi admin panel. Treat every
report seriously and every upgrade as security-relevant.

## Reporting a vulnerability

Email **dev@overpassconnect.com** with the details. Please do not open a public
issue for anything exploitable. You can expect an acknowledgement within 72
hours. Coordinated disclosure is appreciated; we will credit reporters in the
changelog unless you prefer otherwise.

Please include, where possible: the plugin version, Strapi version, identity
provider and version, a minimal reproduction, and the impact you believe it has.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |

The plugin targets Strapi `>=5.24` and is verified up to `5.50.x`. The login
completion step touches Strapi admin internals that are not covered by semver
(see "Known coupling" below), so always test an admin upgrade in staging.

## Design notes relevant to reviewers

- Authorization Code + PKCE (S256) with a signed, HttpOnly transaction cookie
  binding state, nonce, and the PKCE verifier to one browser.
- ID and access tokens are verified against the discovered JWKS with an RS256
  allow-list; `iss`, `aud`/`azp`, `exp`, and `nonce` are enforced. Keycloak's
  `aud=account` access tokens are bound via `azp`.
- Connection and cryptography settings (issuer, client secret, TLS, PKCE,
  state signing) are file/env-only. The admin UI can only edit an allow-listed
  operational subset; every guard that could enable account takeover
  (`requireVerifiedEmail`, `allowEmailRelink`, `allowSuperAdminMapping`, ...)
  is file-only as well.
- SSO can never grant or link to a super admin account unless the file-only
  `allowSuperAdminMapping` is set.
- Back-channel logout validates the logout token (signature, `events`, `jti`
  replay window) and revokes server-side sessions.
- RP-initiated logout verifies the refresh token through Strapi's
  SessionManager before revoking anything; unauthenticated requests cannot
  revoke sessions.

## Known coupling and deployment caveats

- The login completion primes `localStorage['jwtToken']` /
  `['isLoggedIn']`, which are Strapi admin internals. A Strapi upgrade can
  break login without a semver signal. CI runs a scheduled canary against the
  latest Strapi to catch this early.
- Completion ids, the back-channel `jti` replay cache, and rate-limit buckets
  are in-memory and per-process. Multi-instance deployments need sticky
  sessions. Failure mode is closed (login retries), not open.
- Keep at least one local (non-SSO) super admin as break-glass access.
