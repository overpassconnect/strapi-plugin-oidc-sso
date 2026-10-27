'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * Minimal TLS-aware HTTP client built on node core so that a custom CA or a
 * relaxed `rejectUnauthorized` can be applied to *every* provider call,
 * including JWKS fetches. Global `fetch` (undici) does not expose per-request
 * TLS options in a version-stable way, hence this helper.
 */
function request(urlStr, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body = null,
    timeoutMs = 8000,
    ca = null,
    rejectUnauthorized = true,
    maxBytes = 2 * 1024 * 1024, // discovery/JWKS/token JSON are tiny; cap to stop OOM
  } = options;

  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlStr);
    } catch (e) {
      reject(new Error(`Invalid URL: ${urlStr}`));
      return;
    }
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqOptions = {
      method,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      headers: { ...headers },
      timeout: timeoutMs,
    };
    if (isHttps) {
      if (ca) reqOptions.ca = ca;
      if (rejectUnauthorized === false) reqOptions.rejectUnauthorized = false;
    }

    // Hard wall-clock deadline: the socket 'timeout' event is idle-only, so a
    // slow trickle of bytes could otherwise stream forever.
    const deadline = setTimeout(() => {
      req.destroy(new Error(`Request to ${url.hostname} exceeded deadline of ${timeoutMs}ms`));
    }, timeoutMs);

    const req = lib.request(reqOptions, (res) => {
      const chunks = [];
      let received = 0;
      res.on('data', (c) => {
        received += c.length;
        if (received > maxBytes) {
          req.destroy(new Error(`Response body from ${url.hostname} exceeded ${maxBytes} bytes`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        clearTimeout(deadline);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`Request to ${url.hostname} timed out after ${timeoutMs}ms`));
    });
    req.on('error', (err) => {
      clearTimeout(deadline);
      reject(err);
    });

    if (body) req.write(body);
    req.end();
  });
}

async function getJson(urlStr, options = {}) {
  const res = await request(urlStr, options);
  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`GET ${urlStr} returned HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  try {
    return JSON.parse(res.body);
  } catch (e) {
    throw new Error(`GET ${urlStr} returned non-JSON body`);
  }
}

async function postForm(urlStr, form, options = {}) {
  const body = new URLSearchParams(form).toString();
  const res = await request(urlStr, {
    ...options,
    method: 'POST',
    body,
    headers: {
      ...(options.headers || {}),
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
  });
  let json = null;
  try {
    json = JSON.parse(res.body);
  } catch (e) {
    // Non-JSON (e.g. provider error HTML); caller inspects status.
  }
  return { status: res.status, json, raw: res.body };
}

module.exports = { request, getJson, postForm };
