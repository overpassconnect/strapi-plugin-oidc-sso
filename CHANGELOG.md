# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - unreleased

Initial public release.

### Added

- OIDC Authorization Code + PKCE (S256) login for the Strapi v5 admin panel,
  working on the free Community Edition (Strapi >=5.24).
- Provider-generic: any conformant OIDC provider with discovery, JWKS, and the
  code flow. Verified end to end against Keycloak 26.7 and 26.8 on Strapi
  5.50 and 5.59 (develop, and production behind TLS); conformance-tested
  against a strict mock provider.
- Role mapping from IdP realm roles, client roles, or a groups claim to Strapi
  admin roles, with an explicit mapping table and optional convention-based
  dynamic matching (`cms-<key>` group to role by code or name).
- Just-in-time provisioning with verified-email gating, role sync on login,
  and profile sync.
- Admin settings UI (Design System components) for the operational subset;
  connection and security-guard settings are file/env-only by design.
- RP-initiated logout and OIDC Back-Channel Logout (sub and sid resolution,
  jti replay protection, server-side session revocation).
- Break-glass local login preserved; SSO can never grant or link to a super
  admin unless the file-only `allowSuperAdminMapping` is enabled.
- Test suite: 63 logic tests, 17 crypto tests (real jose keypairs), and an
  end-to-end suite of about 95 checks runnable against Keycloak or the bundled
  mock IdP (`tests/e2e/`). It counts the database rows and provider calls
  each login causes, injects provider faults through a preloaded outbound tap,
  and runs in production mode behind a bundled TLS front.

### Fixed (found by the pre-release e2e audit)

- Two concurrent first logins of the same new user (a double-clicked button
  with a live IdP session was enough) created two admin users with the same
  email, because neither the admin email nor the identity subject is unique
  at the database level. Logins for one identity now run one at a time within
  an instance.
- An unreachable token endpoint was reported to the user as `provider_error`
  ("cancelled or failed at the identity provider") and an unreachable JWKS
  endpoint as `id_token_invalid`; both are now `provider_unreachable`.
- A production instance reached over plain HTTP (no TLS, or a proxy Strapi
  does not trust) failed with `provider_error`; it now refuses with
  `session_failed` and logs the configuration to fix.
- The `rpInitiatedLogout` comment claimed Strapi's own logout ends the IdP
  session; it applies to `/oidc-sso/logout` only.

### Security

The pre-release audit history (three internal audit rounds, a spec-conformance
pass against OIDC Core / OAuth 2.1 / PKCE / RP + Back-Channel Logout, and a
live re-audit after the final functional fix) is summarized in
[SECURITY.md](SECURITY.md). Highlights hardened before release: unverified
email account-linking takeover, super-admin escalation via runtime settings,
logout-revocation DoS via unverified cookie claims, and completion-step
session fixation.
