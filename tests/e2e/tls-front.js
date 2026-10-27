'use strict';
/**
 * Test-only TLS-terminating front proxy for production-mode e2e runs. It stands
 * in for the nginx or HAProxy a real deployment puts in front of Strapi:
 *
 *   https://127.0.0.1:<E2E_TLS_PORT>  ->  <E2E_UPSTREAM>
 *
 * adding X-Forwarded-Proto/Host/For as a real proxy does, so Strapi (with
 * `proxy: { koa: true }`) sees the request as secure.
 *
 *   E2E_TLS_CERT, E2E_TLS_KEY  PEM files; a self-signed cert for IP 127.0.0.1 is enough
 *   E2E_TLS_PORT               default 8443
 *   E2E_UPSTREAM               default http://127.0.0.1:1337
 */
const fs = require('fs');
const http = require('http');
const https = require('https');

const port = Number(process.env.E2E_TLS_PORT || 8443);
const upstream = new URL(process.env.E2E_UPSTREAM || 'http://127.0.0.1:1337');

const server = https.createServer(
  { cert: fs.readFileSync(process.env.E2E_TLS_CERT), key: fs.readFileSync(process.env.E2E_TLS_KEY) },
  (req, res) => {
    const headers = {
      ...req.headers,
      'x-forwarded-proto': 'https',
      'x-forwarded-host': req.headers.host,
      'x-forwarded-for': req.socket.remoteAddress,
    };
    const out = http.request(
      { hostname: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers },
      (up) => {
        res.writeHead(up.statusCode, up.headers);
        up.pipe(res);
      }
    );
    out.on('error', (err) => {
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end(`upstream error: ${err.message}`);
    });
    req.pipe(out);
  }
);

server.listen(port, '127.0.0.1', () => {
  console.log(`tls-front listening on https://127.0.0.1:${port} -> ${upstream.origin}`);
});
