'use strict';

const crypto = require('crypto');

/** URL-safe base64 without padding (RFC 7636 / JWT style). */
function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Cryptographically random URL-safe string of `bytes` entropy. */
function randomToken(bytes = 32) {
  return base64url(crypto.randomBytes(bytes));
}

/** PKCE: create a verifier and its S256 challenge. */
function createPkcePair() {
  const verifier = randomToken(32); // 43 chars, within RFC 7636 bounds
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: 'S256' };
}

/** Constant-time comparison for equal-length secrets/tokens. */
function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

/** Detached HMAC-SHA256 signature over a string, returned base64url. */
function hmac(secret, data) {
  return base64url(crypto.createHmac('sha256', secret).update(data).digest());
}

module.exports = {
  base64url,
  randomToken,
  createPkcePair,
  timingSafeEqual,
  hmac,
};
