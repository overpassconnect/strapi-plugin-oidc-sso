'use strict';

/**
 * Errors that are safe to surface (as a short code) to the browser via the
 * login page. The `code` is shown to the user; `detail` is logged server-side
 * only and never leaks token material.
 */
class SsoError extends Error {
  constructor(code, detail, { status = 401 } = {}) {
    super(detail || code);
    this.name = 'SsoError';
    this.code = code;
    this.detail = detail;
    this.status = status;
  }
}

const Codes = {
  DISABLED: 'sso_disabled',
  DISCOVERY_FAILED: 'provider_unreachable',
  // Same browser code as DISCOVERY_FAILED: any provider endpoint we could not
  // reach (token, JWKS) is an outage, not a failed or forged sign-in.
  PROVIDER_UNREACHABLE: 'provider_unreachable',
  STATE_INVALID: 'state_invalid',
  STATE_EXPIRED: 'state_expired',
  CODE_EXCHANGE_FAILED: 'code_exchange_failed',
  ID_TOKEN_INVALID: 'id_token_invalid',
  NONCE_MISMATCH: 'nonce_mismatch',
  ACCESS_TOKEN_INVALID: 'access_token_invalid',
  NO_EMAIL: 'no_email',
  EMAIL_UNVERIFIED: 'email_unverified',
  NO_ROLE: 'no_mapped_role',
  RELINK_REFUSED: 'email_relink_refused',
  USER_INACTIVE: 'user_inactive',
  PROVISIONING_FAILED: 'provisioning_failed',
  SESSION_FAILED: 'session_failed',
  PROVIDER_ERROR: 'provider_error',
};

module.exports = { SsoError, Codes };
