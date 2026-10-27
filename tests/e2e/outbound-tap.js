'use strict';
/**
 * Test-only preload for the Strapi process under e2e test:
 *
 *   NODE_OPTIONS="--require /path/to/tests/e2e/outbound-tap.js"
 *
 * 1. Counting. Every outbound http/https request is appended as one JSON line
 *    ({ ts, pid, method, url }) to the file named by E2E_OUTBOUND_LOG, so the
 *    flow test can assert exactly how many provider calls each login makes.
 * 2. Fault injection. While the file named by E2E_FAULT_FILE exists and holds
 *    { "match": "<url substring>", "mode": "<mode>", "count": <n> }, the next
 *    <n> matching requests are faulted, then the file is removed:
 *      refuse   the connection fails at once with ECONNREFUSED
 *      hang     the connection is accepted and never answered
 *      garbage  HTTP 200 with an HTML body instead of JSON
 *      status   HTTP <status> (default 500) with a JSON error body
 *
 * Never load this outside tests: it rewrites outbound requests on demand.
 */
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');

const LOG = process.env.E2E_OUTBOUND_LOG || '';
const FAULT = process.env.E2E_FAULT_FILE || '';

// Local stand-ins for the faulty far end. unref() so they never keep a process
// alive; they only matter once a fault is armed, long after boot.
let hangPort = 0;
let stubPort = 0;
if (FAULT) {
  const hang = net.createServer(() => { /* accept, never answer */ });
  hang.listen(0, '127.0.0.1', () => { hangPort = hang.address().port; });
  hang.unref();
  const stub = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://stub');
    if (u.pathname === '/garbage') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body>upstream proxy error page</body></html>');
      return;
    }
    const status = Number(u.searchParams.get('status')) || 500;
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'server_error', error_description: 'e2e injected fault' }));
  });
  stub.listen(0, '127.0.0.1', () => { stubPort = stub.address().port; });
  stub.unref();
}

function describeTarget(proto, args) {
  let opts = {};
  let url = null;
  if (typeof args[0] === 'string' || args[0] instanceof URL) {
    url = new URL(String(args[0]));
    if (args[1] && typeof args[1] === 'object' && typeof args[1] !== 'function') opts = args[1];
  } else if (args[0] && typeof args[0] === 'object') {
    opts = args[0];
  }
  const host = opts.hostname || opts.host || (url && url.hostname) || 'localhost';
  const port = opts.port || (url && url.port) || (proto === 'https' ? 443 : 80);
  const path = opts.path || (url && url.pathname + url.search) || '/';
  return { method: String(opts.method || 'GET').toUpperCase(), url: `${proto}://${host}:${port}${path}` };
}

/** Return the armed fault for this URL (consuming one use), or null. */
function takeFault(targetUrl) {
  if (!FAULT || !fs.existsSync(FAULT)) return null;
  let spec;
  try {
    spec = JSON.parse(fs.readFileSync(FAULT, 'utf8'));
  } catch (e) {
    return null;
  }
  if (!spec || typeof spec.match !== 'string' || !targetUrl.includes(spec.match)) return null;
  const remaining = (Number(spec.count) || 1) - 1;
  if (remaining > 0) fs.writeFileSync(FAULT, JSON.stringify({ ...spec, count: remaining }));
  else fs.rmSync(FAULT, { force: true });
  return spec;
}

function refusedSocket() {
  const socket = new net.Socket();
  process.nextTick(() => {
    const err = new Error('connect ECONNREFUSED (e2e injected fault)');
    err.code = 'ECONNREFUSED';
    socket.destroy(err);
  });
  return socket;
}

function applyFault(spec, opts) {
  const faulted = { ...opts, agent: undefined };
  delete faulted.createConnection;
  if (spec.mode === 'refuse') {
    faulted.createConnection = refusedSocket;
    return faulted;
  }
  if (spec.mode === 'hang' && hangPort) {
    return { ...faulted, hostname: '127.0.0.1', host: undefined, port: hangPort };
  }
  if ((spec.mode === 'garbage' || spec.mode === 'status') && stubPort) {
    const path = spec.mode === 'garbage' ? '/garbage' : `/status?status=${Number(spec.status) || 500}`;
    return { ...faulted, hostname: '127.0.0.1', host: undefined, port: stubPort, path };
  }
  faulted.createConnection = refusedSocket; // stand-in not ready yet: fail closed
  return faulted;
}

for (const [proto, mod] of [['http', http], ['https', https]]) {
  const original = mod.request;
  mod.request = function tappedRequest(...args) {
    const target = describeTarget(proto, args);
    if (LOG) {
      fs.appendFileSync(LOG, `${JSON.stringify({ ts: Date.now(), pid: process.pid, ...target })}\n`);
    }
    const spec = takeFault(target.url);
    // Faults are applied to the options-object form, which is what the plugin's
    // http client uses. Other call shapes pass through untouched.
    if (spec && args[0] && typeof args[0] === 'object' && !(args[0] instanceof URL)) {
      // A faulted https request is served by a plain-TCP stand-in, so it goes
      // out through http.
      const lib = spec.mode === 'refuse' ? mod : http;
      const call = lib === mod ? original : http.request.__original;
      return call.call(lib, applyFault(spec, args[0]), ...args.slice(1));
    }
    return original.apply(this, args);
  };
  mod.request.__original = original;
}
