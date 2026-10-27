'use strict';

/**
 * Tiny in-memory sliding-window limiter. Per-instance (not shared across a
 * cluster), which is fine as a brute-force/abuse dampener on the callback and
 * login endpoints - the real security is the signed state and PKCE, not this.
 */
const buckets = new Map();

function allow(key, limit, windowMs) {
  const now = Date.now();
  const hits = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  hits.push(now);
  buckets.set(key, hits);

  // Opportunistic cleanup so the map cannot grow unbounded.
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) {
      if (!v.length || now - v[v.length - 1] > windowMs) buckets.delete(k);
    }
  }
  return hits.length <= limit;
}

/**
 * Convenience for controllers: if the key is over budget, write the standard
 * 429 response and return true (caller should `return`); otherwise return false.
 * Keeps the throttle response identical across every endpoint.
 */
function limited(ctx, key, limit, windowMs) {
  if (allow(key, limit, windowMs)) return false;
  ctx.status = 429;
  ctx.body = { error: 'too_many_requests' };
  return true;
}

module.exports = { allow, limited };
