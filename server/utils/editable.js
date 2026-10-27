'use strict';

/**
 * The runtime-editable settings surface: exactly which config keys may be
 * overridden from the admin UI / database, with validators.
 *
 * Everything NOT listed here is file/env-only by design. In particular the
 * connection and cryptography settings (issuer, clientId, clientSecret, TLS,
 * PKCE, token validation, state signing, logout URIs) must never be editable
 * from a browser session: a compromised admin account could otherwise repoint
 * authentication itself. The editable set below is operational policy - the
 * same authority an admin with user/role management already holds.
 */

const ROLE_SOURCES = ['realm', 'client', 'groups'];
const MATCH_BY = ['code', 'name'];

const isBool = (v) => typeof v === 'boolean';
const isStr = (v) => typeof v === 'string';
const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);

// Own-property check only - never traverse the prototype chain, so adversarial
// key names (hasOwnProperty, __proto__, constructor, toString, …) can neither
// pass the whitelist gate nor resolve a bogus "validator".
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function objectValidator(shape, label) {
  return (v) => {
    if (!isObj(v)) return `${label} must be an object`;
    for (const [k, val] of Object.entries(v)) {
      if (!hasOwn(shape, k)) return `${label}.${k} is not a recognised setting`;
      const err = shape[k](val);
      if (err) return `${label}.${err}`;
    }
    return null;
  };
}

// Editable = operational convenience. The following are FILE/ENV-ONLY and are
// intentionally NOT here, because each one either weakens an account-takeover
// guard or grants privilege, and settings.update is a grantable permission:
//   requireVerifiedEmail, matchExistingByEmail, allowEmailRelink,
//   reactivateDisabledOnLogin, protectLastSuperAdmin, allowSuperAdminMapping,
//   and everything under connection/crypto.
// Nested shapes are named so the SAME allow-list drives both write-time
// validation and the read-time merge (so a directly-tampered store row still
// cannot inject a non-whitelisted nested key like requireVerifiedEmail).
const DYNAMIC_SHAPE = {
  enabled: (v) => (isBool(v) ? null : 'enabled must be a boolean'),
  groupPrefix: (v) => (isStr(v) && v.trim().length > 0 ? null : 'groupPrefix must be a non-empty string'),
  matchBy: (v) =>
    Array.isArray(v) && v.length > 0 && v.every((s) => MATCH_BY.includes(s))
      ? null
      : `matchBy must be a non-empty array drawn from: ${MATCH_BY.join(', ')}`,
};
const PROVISIONING_SHAPE = {
  autoCreate: (v) => (isBool(v) ? null : 'autoCreate must be a boolean'),
  defaultRoleId: (v) => (v === null || Number.isInteger(v) ? null : 'defaultRoleId must be a role id or null'),
  syncRolesOnLogin: (v) => (isBool(v) ? null : 'syncRolesOnLogin must be a boolean'),
  updateProfileOnLogin: (v) => (isBool(v) ? null : 'updateProfileOnLogin must be a boolean'),
};
const NESTED_SHAPES = { dynamicRoleMatching: DYNAMIC_SHAPE, provisioning: PROVISIONING_SHAPE };

const EDITABLE = {
  roleMapping: (v) => {
    if (!isObj(v)) return 'roleMapping must be an object of { idpGroupOrRole: strapiRoleIdOrCode }';
    const keys = Object.keys(v);
    if (keys.length > 256) return 'roleMapping has too many entries (max 256)';
    for (const [k, t] of Object.entries(v)) {
      if (!k.trim()) return 'roleMapping keys must be non-empty names';
      if (k.length > 128) return `roleMapping key "${k.slice(0, 16)}…" is too long (max 128)`;
      if (!(isStr(t) || Number.isInteger(t))) return `roleMapping["${k}"] must be a Strapi role id or code`;
    }
    return null;
  },
  roleSources: (v) =>
    Array.isArray(v) && v.length > 0 && v.every((s) => ROLE_SOURCES.includes(s))
      ? null
      : `roleSources must be a non-empty array drawn from: ${ROLE_SOURCES.join(', ')}`,
  groupsClaim: (v) => (isStr(v) && v.trim().length > 0 ? null : 'groupsClaim must be a non-empty string'),
  resourceRolesClient: (v) => (isStr(v) ? null : 'resourceRolesClient must be a string'),
  dynamicRoleMatching: objectValidator(DYNAMIC_SHAPE, 'dynamicRoleMatching'),
  provisioning: objectValidator(PROVISIONING_SHAPE, 'provisioning'),
  rememberMe: (v) => (isBool(v) ? null : 'rememberMe must be a boolean'),
  hideLocalLogin: (v) => (isBool(v) ? null : 'hideLocalLogin must be a boolean'),
  // NOTE: `audit` is intentionally NOT editable at runtime. If it were, a holder
  // of settings.update could disable the audit trail (suppressing the record of
  // that very change and all subsequent auth/role events). File/env-only.
  buttonLabel: (v) =>
    isStr(v) && v.trim().length > 0 && v.length <= 60
      ? null
      : 'buttonLabel must be a non-empty string of at most 60 characters',
};

/** Validate a full settings object. Returns an array of error strings (empty = valid). */
function validateSettings(settings) {
  if (!isObj(settings)) return ['settings must be an object'];
  const errors = [];
  for (const [key, value] of Object.entries(settings)) {
    if (!hasOwn(EDITABLE, key)) {
      errors.push(`"${key}" is not editable at runtime (file/env configuration only)`);
      continue;
    }
    const err = EDITABLE[key](value);
    if (err) errors.push(err);
  }
  return errors;
}

/** Merge DB overrides over file config; only whitelisted keys are honoured. */
function mergeEditable(fileCfg, overrides) {
  if (!isObj(overrides) || Object.keys(overrides).length === 0) return fileCfg;
  const merged = { ...fileCfg };
  for (const [key, value] of Object.entries(overrides)) {
    if (!hasOwn(EDITABLE, key)) continue; // defense in depth if the store was tampered with
    if (hasOwn(NESTED_SHAPES, key)) {
      // Only copy nested keys that are themselves whitelisted - so a tampered
      // store cannot smuggle a file-only key (e.g. requireVerifiedEmail) in via
      // the provisioning object.
      const allowed = NESTED_SHAPES[key];
      const clean = {};
      if (isObj(value)) {
        for (const [k, vv] of Object.entries(value)) {
          if (hasOwn(allowed, k)) clean[k] = vv;
        }
      }
      merged[key] = { ...(fileCfg[key] || {}), ...clean };
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

/** Project the editable subset out of an effective config (for the UI). */
function pickEditable(cfg) {
  const out = {};
  for (const key of Object.keys(EDITABLE)) {
    if (cfg[key] !== undefined) out[key] = cfg[key];
  }
  return out;
}

/** True only for a plain object (rejects arrays, strings, null, etc.). */
function isPlainSettingsObject(v) {
  return isObj(v);
}

module.exports = { EDITABLE, validateSettings, mergeEditable, pickEditable, isPlainSettingsObject };
